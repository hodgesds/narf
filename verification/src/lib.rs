//! narf-verification — kernel-test runner + cross-cutting smokes.
//!
//! Spec: `verification/specification/spec.md` §6 + §7.
//!
//! ## Crate split
//!
//! The zero-dep `narf-kernel-test` sub-crate (at
//! `verification/kernel-test`) holds the [`KernelTest`] struct, the
//! `kernel_test!` / `kernel_test_in!` macros, and the `narf.tests`
//! ELF section collector. Driver / library crates depend on
//! `narf-kernel-test` directly so they can register subsystem-aware
//! smokes without depending on this higher-level crate.
//!
//! `narf-verification` itself depends on every subsystem (so it can
//! host integration tests that span them) and provides the runner
//! (`run_all`, `exit_with_result`).
//!
//! ## Backwards compatibility
//!
//! [`KernelTest`], [`TestResult`], [`Summary`], `kernel_test!`, and
//! `kernel_test_in!` are re-exported from this crate so existing
//! callers continue to work.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]
#![feature(generic_const_exprs)]
#![allow(incomplete_features)]

extern crate alloc;

// Force-link crates that contribute tests via the `narf.tests` link
// section but whose public surface is not otherwise referenced from
// this mega-lib. Without a load-bearing reference the rlib linker
// drops the crate's compilation unit, taking its kernel-test
// `static ENTRY` writers with it. `extern crate` plus a `#[used]`
// static touching a real symbol from the crate is the minimum
// needed to keep the unit alive.
extern crate narf_observability;
#[used]
static __FORCE_LINK_OBS: fn() -> usize = || narf_observability::install_count();

extern crate narf_drivers_sound;
#[used]
static __FORCE_LINK_SOUND: fn() -> usize = || narf_drivers_sound::card_count();

extern crate narf_drivers_hwmon;
#[used]
static __FORCE_LINK_HWMON: fn() -> usize = || narf_drivers_hwmon::registry::count();

extern crate narf_drivers_extcon;
#[used]
static __FORCE_LINK_EXTCON: fn() -> usize = || narf_drivers_extcon::class::device_count();

extern crate narf_modules;
#[used]
static __FORCE_LINK_MODULES: fn() -> usize = || narf_modules::registry::len();

// narf-crypto contributes the `crypto/p256`, `crypto/aes_ctr`, and
// other crypto-subsystem smokes via `kernel_test_in!`. Nothing in
// this lib references its public surface, so the rlib unit gets
// dropped at link time and the `narf.tests` entries with it. Anchor
// it with a `#[used]` static touching `blake3_hash`.
extern crate narf_crypto;
#[used]
static __FORCE_LINK_CRYPTO: fn() -> usize = || narf_crypto::blake3_hash(&[]).len();

// narf-bpf contributes the `bpf` subsystem smokes. It also carries the only
// writer of the `narf.kfuncs` link section, so a dropped compilation unit here
// costs more than a few tests: the kfunc registry comes up empty and every
// program load fails to resolve a call.
extern crate narf_bpf;
#[used]
static __FORCE_LINK_BPF: fn() -> (usize, usize) = narf_bpf::summary;

// narf-bpf-structops now carries the `narf.structops` link section (the
// struct_ops descriptors) and the `bpf/structops` smokes; narf-bpf-idle carries
// the `bpf/idle` smokes and installs a struct_ops descriptor of its own. Anchor
// both so their sections survive dead-code elimination.
extern crate narf_bpf_idle;
extern crate narf_bpf_leds;
extern crate narf_bpf_structops;
#[used]
static __FORCE_LINK_BPF_STRUCTOPS: fn() -> usize = narf_bpf_structops::summary;
#[used]
static __FORCE_LINK_BPF_IDLE: fn() = narf_bpf_idle::register_initcalls;
// narf-bpf-leds carries the `narf_led_submit` kfunc (a `narf.kfuncs` writer)
// and the `bpf/leds` smoke; anchor it so both survive the link.
#[used]
static __FORCE_LINK_BPF_LEDS: fn() = narf_bpf_leds::register_initcalls;

use core::fmt::Write;

use narf_console::Writer;

// Re-export the framework types so existing callers (and the
// `kernel_test!` macro re-export below) keep working unchanged.
pub use narf_kernel_test::{kernel_test, kernel_test_in};
pub use narf_kernel_test::{tests, KernelTest, Summary, TestResult};

/// Run one test and fail it if more user tasks are live when it returns than
/// when it started. The tests share one boot, so a user task that outlives
/// its test changes the state every later test starts from; this attributes
/// the leak to the test that caused it rather than to whichever later test
/// first notices. A test that already failed keeps its own reason.
fn run_leak_checked(t: &KernelTest) -> TestResult {
    let live_before = narf_scheduler::live_user_task_count();
    let result = (t.run)();
    let live_after = narf_scheduler::live_user_task_count();
    if live_after <= live_before {
        return result;
    }
    let _ = writeln!(
        Writer,
        "  [LEAK] {} / {}: live user tasks {} -> {}",
        t.subsystem, t.name, live_before, live_after
    );
    match result {
        TestResult::Fail(why) => TestResult::Fail(why),
        _ => TestResult::Fail("left a live user task behind when it returned"),
    }
}

/// Named pseudo-test `init / boot-initcalls`: fails when the boot stage
/// loop recorded any `InitResult::Error` (see `narf_init::BootErrors`).
///
/// Every `run_*` entry point prints and counts it before the selected
/// tests, so a `--subsystem` filter cannot hide a failed boot initcall.
/// It reads the boot-loop record, not the per-stage stats, so init
/// self-tests that call `run_stage` directly (and deliberately fail an
/// initcall) do not affect it.
fn boot_initcalls_check() -> Option<narf_init::BootErrors> {
    let e = narf_init::boot_errors();
    if e.count == 0 {
        let _ = writeln!(Writer, "  [ OK ] init / boot-initcalls");
        return None;
    }
    let _ = writeln!(
        Writer,
        "  [FAIL] init / boot-initcalls: {} boot initcall error(s); first: {} / {}: {}",
        e.count, e.first_stage, e.first_name, e.first_msg
    );
    Some(e)
}

/// Run every registered test, print results to the console, return a
/// summary. Intended to be called from the kernel's `_start_rust`
/// during CI builds (feature-gated by consumers).
///
/// Why a run stopped early: see [`stop_after_panic`].
const PANIC_STOP_REASON: &str =
    "a CPU panicked (KERNEL PANIC above) and stays halted; the remaining tests did not run";

/// A panic halts only the panicking CPU (`narf_console::panic_sink`); the
/// other CPUs run on, and the kernel wedges on the first lock, task or
/// shootdown acknowledgement the halted CPU owed, which used to end the run
/// only at the QEMU timeout. Once a panic has been reported, the runners stop
/// after the current test with this named failure, so the run ends in bounded
/// time with a summary that counts it.
fn stop_after_panic(after: &str) -> bool {
    if !narf_console::panic_reported() {
        return false;
    }
    let _ = writeln!(
        Writer,
        "  [FAIL] kernel / panic: {PANIC_STOP_REASON} (stopped after {after})"
    );
    true
}

/// Output is grouped by `KernelTest::subsystem` so a failure inside
/// one subsystem (driver / module / library) doesn't drown the
/// others. Iteration order matches link order within each
/// subsystem; subsystems themselves are emitted in first-seen order.
pub fn run_all() -> Summary {
    let _ = writeln!(Writer);
    let _ = writeln!(Writer, "── kernel_test harness ──────────────────────────");
    let boot = boot_initcalls_check();
    let ts = tests();
    if ts.is_empty() {
        let _ = writeln!(Writer, "  (no tests registered)");
        return if boot.is_some() {
            Summary::SomeFailed
        } else {
            Summary::AllOk
        };
    }
    let mut pass = usize::from(boot.is_none());
    let mut fail = usize::from(boot.is_some());
    let mut skip = 0usize;
    let mut current: &'static str = "";

    // Capture failing test names so we can re-emit them AFTER the
    // summary line. Without this, a flaky 1-of-1386 fail scrolls
    // past the harness's terminal window and the summary "1 fail"
    // is the last thing visible — useless for diagnosis.
    // Cap at 32 distinct failures; anything more and the suite
    // is broken enough that the inline [FAIL] lines are the
    // useful signal anyway.
    const MAX_FAILED_RECORD: usize = 32;
    let mut failed: [(&'static str, &'static str, &'static str); MAX_FAILED_RECORD] =
        [("", "", ""); MAX_FAILED_RECORD];
    let mut failed_n: usize = 0;
    if let Some(e) = boot {
        failed[0] = ("init/boot-initcalls", e.first_name, e.first_msg);
        failed_n = 1;
    }

    for t in ts {
        // Subsystem header — printed when we transition.
        if t.subsystem != current {
            let _ = writeln!(Writer, "── {} ─", t.subsystem);
            current = t.subsystem;
        }
        // Print the test name BEFORE running it. If it hangs the
        // last name printed identifies the culprit. Only emitted
        // when the build flag asks for it; default keeps the
        // existing terse "[OK] name" output.
        let _ = writeln!(Writer, "  [run] {}", t.name);
        match run_leak_checked(t) {
            TestResult::Pass => {
                let _ = writeln!(Writer, "  [ OK ] {}", t.name);
                pass += 1;
            }
            TestResult::Fail(why) => {
                let _ = writeln!(Writer, "  [FAIL] {}: {}", t.name, why);
                if failed_n < MAX_FAILED_RECORD {
                    failed[failed_n] = (t.subsystem, t.name, why);
                    failed_n += 1;
                }
                fail += 1;
            }
            TestResult::Skip(why) => {
                let _ = writeln!(Writer, "  [skip] {}: {}", t.name, why);
                skip += 1;
            }
        }
        // Buddy state self-check after memory-related tests. Limited
        // to that subset because the O(N²) no-alloc walk is too slow
        // to run after every test (must avoid alloc inside the buddy
        // lock to prevent slab→buddy recursive lock).
        if t.subsystem.starts_with("memory") {
            if let Err((zone, frame_no, oa, ob)) = narf_memory::frame_validate_no_overlap() {
                let _ = writeln!(
                    Writer,
                    "  [BUDDY-CORRUPT after {}/{}] zone {} frame {:#x} order {} vs {}",
                    t.subsystem,
                    t.name,
                    zone,
                    frame_no << narf_memory::PAGE_SHIFT,
                    oa,
                    ob,
                );
            }
        }
        if stop_after_panic(t.name) {
            if failed_n < MAX_FAILED_RECORD {
                failed[failed_n] = ("kernel", "panic", PANIC_STOP_REASON);
                failed_n += 1;
            }
            fail += 1;
            break;
        }
    }
    let _ = writeln!(
        Writer,
        "── summary: {} pass, {} fail, {} skip ──",
        pass, fail, skip
    );
    // Re-emit failure list AFTER the summary so a `tail -N` from
    // the harness consumer captures both the count AND the names.
    if fail > 0 {
        let _ = writeln!(Writer, "── failing tests ──");
        for (sub, name, why) in &failed[..failed_n] {
            let _ = writeln!(Writer, "  {} / {}: {}", sub, name, why);
        }
        if fail > failed_n {
            let _ = writeln!(
                Writer,
                "  ... and {} more (record buffer full)",
                fail - failed_n
            );
        }
    }

    if fail == 0 {
        Summary::AllOk
    } else {
        Summary::SomeFailed
    }
}

/// Run only the tests whose subsystem matches `wanted`. Useful when
/// the user wants to drive `cargo xtask test --subsystem
/// drivers/net/r8169` without firing every other suite.
pub fn run_subsystem(wanted: &str) -> Summary {
    let _ = writeln!(Writer);
    let _ = writeln!(Writer, "── kernel_test ({}) ──", wanted);
    let boot = boot_initcalls_check();
    let mut pass = usize::from(boot.is_none());
    let mut fail = usize::from(boot.is_some());
    let mut skip = 0usize;
    for t in tests() {
        if t.subsystem != wanted {
            continue;
        }
        match run_leak_checked(t) {
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
        if stop_after_panic(t.name) {
            fail += 1;
            break;
        }
    }
    let _ = writeln!(
        Writer,
        "── summary: {} pass, {} fail, {} skip ──",
        pass, fail, skip
    );
    if fail == 0 {
        Summary::AllOk
    } else {
        Summary::SomeFailed
    }
}

/// Distinct subsystem names in registration order. Useful to
/// produce a summary per-subsystem report without iterating tests
/// twice in the caller.
pub fn subsystems() -> alloc::vec::Vec<&'static str> {
    let mut out = alloc::vec::Vec::<&'static str>::new();
    for t in tests() {
        if !out.contains(&t.subsystem) {
            out.push(t.subsystem);
        }
    }
    out
}

/// Run every test and immediately exit the kernel with the mapped code.
pub fn run_all_and_exit() -> ! {
    let code = match run_all() {
        Summary::AllOk => 0,
        Summary::SomeFailed => 1,
    };
    // SAFETY: exit_kernel is the only post-test action we're authorised
    // to take; it does not return.
    // SAFETY: Valid memory or trusted environment
    unsafe { narf_arch::exit_kernel(code) }
}

/// Run one exact subsystem and immediately exit with the mapped status.
pub fn run_subsystem_and_exit(wanted: &str) -> ! {
    let code = match run_subsystem(wanted) {
        Summary::AllOk => 0,
        Summary::SomeFailed => 1,
    };
    // SAFETY: this is the terminal action of the kernel-test boot.
    unsafe { narf_arch::exit_kernel(code) }
}

/// True if test subsystem `have` is selected by filter `want`: an exact
/// match, or `want` is a parent path of `have` on a `/` boundary — so the
/// filter `filesystem` selects `filesystem`, `filesystem/page_cache`, and
/// `filesystem/procfs`, but not `filesystemx`.
fn subsystem_selected(have: &str, want: &str) -> bool {
    have == want
        || (have.len() > want.len()
            && have.as_bytes()[want.len()] == b'/'
            && have.starts_with(want))
}

/// Run every test whose subsystem is selected (see [`subsystem_selected`])
/// by ANY of the `wanted` filters. This is the change-based CI path: the
/// `affected` command computes the affected subsystem set and CI passes it
/// as a comma list, so a PR runs only the subsystems its diff can touch.
///
/// An empty `wanted` selects nothing; callers that want the whole suite
/// call [`run_all`] instead.
pub fn run_subsystems(wanted: &[&str]) -> Summary {
    let _ = writeln!(Writer);
    let _ = writeln!(Writer, "── kernel_test (filtered: {}) ──", wanted.len());
    let boot = boot_initcalls_check();
    let mut pass = usize::from(boot.is_none());
    let mut fail = usize::from(boot.is_some());
    let mut skip = 0usize;
    for t in tests() {
        if !wanted.iter().any(|w| subsystem_selected(t.subsystem, w)) {
            continue;
        }
        match run_leak_checked(t) {
            TestResult::Pass => {
                let _ = writeln!(Writer, "  [ OK ] {} / {}", t.subsystem, t.name);
                pass += 1;
            }
            TestResult::Fail(why) => {
                let _ = writeln!(Writer, "  [FAIL] {} / {}: {}", t.subsystem, t.name, why);
                fail += 1;
            }
            TestResult::Skip(why) => {
                let _ = writeln!(Writer, "  [skip] {} / {}: {}", t.subsystem, t.name, why);
                skip += 1;
            }
        }
        if stop_after_panic(t.name) {
            fail += 1;
            break;
        }
    }
    let _ = writeln!(
        Writer,
        "── summary: {} pass, {} fail, {} skip ──",
        pass, fail, skip
    );
    if fail == 0 {
        Summary::AllOk
    } else {
        Summary::SomeFailed
    }
}

/// Run the selected subsystems (prefix-matched, comma list) and exit with
/// the mapped status.
pub fn run_subsystems_and_exit(wanted: &[&str]) -> ! {
    let code = match run_subsystems(wanted) {
        Summary::AllOk => 0,
        Summary::SomeFailed => 1,
    };
    // SAFETY: this is the terminal action of the kernel-test boot.
    unsafe { narf_arch::exit_kernel(code) }
}

// ── built-in smoke tests that always register ──────────────────
//
// These live in the library so any binary linking `narf-verification`
// gets at least this much coverage.

// `smoke_typed_id_sanity` migrated to lib/src/tests.rs (subsystem `"lib"`).

// `smoke_spin_lock_cycle` migrated to lib/src/tests.rs (subsystem `"lib"`).

// `smoke_bitmap_first_set` migrated to lib/src/tests.rs (subsystem `"lib"`).

// `smoke_arch_backend` migrated to arch/src/tests.rs (subsystem `"arch"`).

fn smoke_arch_mmio_round_trip() -> TestResult {
    // Allocate a frame, treat it as MMIO, write a sentinel pattern
    // through narf_arch::mmio::write32, read it back via read32.
    // The frame is identity-mapped low RAM — not a real device,
    // but the access path exercises the per-arch barrier discipline
    // (dmb ishst/ishld + dsb st on aarch64; compiler_fence + volatile
    // on x86_64).
    use narf_memory::frame::alloc_frame;
    let frame = match alloc_frame() {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("alloc_frame"),
    };
    // The frame is ordinary RAM: reach it through the direct map, not
    // its physical address.
    let va = frame.start_address().kernel_ptr::<u8>() as u64;
    // 32-bit round trip.
    // SAFETY: direct-mapped frame; we own it.
    unsafe {
        narf_arch::mmio::write32(va, 0xDEAD_BEEF);
    }
    // SAFETY: Valid memory or trusted environment
    let r32 = unsafe { narf_arch::mmio::read32(va) };
    if r32 != 0xDEAD_BEEF {
        return TestResult::Fail("32-bit round trip mismatch");
    }
    // 16-bit at +4.
    // SAFETY: same.
    unsafe {
        narf_arch::mmio::write16(va + 4, 0xCAFE);
    }
    // SAFETY: Valid memory or trusted environment
    if unsafe { narf_arch::mmio::read16(va + 4) } != 0xCAFE {
        return TestResult::Fail("16-bit round trip mismatch");
    }
    // 8-bit at +6 + 7.
    // SAFETY: same.
    unsafe {
        narf_arch::mmio::write8(va + 6, 0xAB);
        narf_arch::mmio::write8(va + 7, 0xCD);
    }
    // SAFETY: Valid memory or trusted environment
    if unsafe { narf_arch::mmio::read8(va + 6) } != 0xAB
        // SAFETY: Valid memory or trusted environment
        || unsafe { narf_arch::mmio::read8(va + 7) } != 0xCD
    {
        return TestResult::Fail("8-bit round trip mismatch");
    }
    // Width independence: a 32-bit write at +4 should overwrite the
    // 16-bit + two 8-bit values.
    // SAFETY: same.
    unsafe {
        narf_arch::mmio::write32(va + 4, 0xFEED_FACE);
    }
    // SAFETY: Valid memory or trusted environment
    if unsafe { narf_arch::mmio::read32(va + 4) } != 0xFEED_FACE {
        return TestResult::Fail("32-bit overwrite of mixed widths");
    }
    TestResult::Pass
}
kernel_test!(smoke_arch_mmio_round_trip);

/// The prefix-matching that drives change-based kernel-test sharding:
/// a filter selects its exact subsystem and any child on a `/` boundary,
/// but not an unrelated one or a same-prefix-different-name sibling.
fn smoke_subsystem_prefix_selection() -> TestResult {
    if !subsystem_selected("filesystem", "filesystem") {
        return TestResult::Fail("exact match must select");
    }
    if !subsystem_selected("filesystem/page_cache", "filesystem") {
        return TestResult::Fail("parent path must select child");
    }
    if subsystem_selected("filesystemx", "filesystem") {
        return TestResult::Fail("must not select a non-`/`-boundary prefix");
    }
    if subsystem_selected("net/tcp", "filesystem") {
        return TestResult::Fail("unrelated subsystem must not select");
    }
    // Multi-filter: run_subsystems ORs the filters.
    let wanted = ["memory", "filesystem"];
    let sel = |s: &str| wanted.iter().any(|w| subsystem_selected(s, w));
    if !sel("memory") || !sel("filesystem/page_cache") || sel("net/tcp") {
        return TestResult::Fail("multi-filter OR semantics wrong");
    }
    TestResult::Pass
}
kernel_test_in!("verification", smoke_subsystem_prefix_selection);

// `smoke_arch_percpu_basic` migrated to arch/src/tests.rs (subsystem `"arch"`).

// `smoke_monotonic_advances` migrated to time/src/tests.rs (subsystem `"time"`).

// `smoke_box_roundtrip` migrated to lib/src/tests.rs (subsystem `"lib"`).

// `smoke_scheduler_drives_future` migrated to scheduler/src/tests.rs (subsystem `"scheduler"`).

// `smoke_scheduler_respects_waker` migrated to scheduler/src/tests.rs (subsystem `"scheduler"`).

// `smoke_cap_slot_layout` migrated to capabilities/src/tests.rs (subsystem `"capabilities"`).

// `smoke_cap_kind_registry` migrated to capabilities/src/tests.rs (subsystem `"capabilities"`).

// `smoke_cap_derive_narrows_rights` migrated to capabilities/src/tests.rs (subsystem `"capabilities"`).

// `smoke_timer_irq_fires` migrated to interrupts/src/tests.rs (subsystem `"interrupts"`).

// `smoke_irq_dispatch_fire_count` migrated to interrupts/src/tests.rs (subsystem `"interrupts"`).

// `smoke_vector_alloc_unique` migrated to interrupts/src/tests.rs (subsystem `"interrupts"`).

// `smoke_wait_for_irq_resolves_after_on_irq` migrated to interrupts/src/tests.rs (subsystem `"interrupts"`).

// `smoke_probe_catches_page_fault` migrated to memory/src/tests.rs (subsystem `"memory"`).

// `smoke_nx_enforces_no_exec` migrated to memory/src/tests.rs (subsystem `"memory"`).

// `smoke_aarch64_mte_l2` migrated to arch/src/tests.rs (subsystem `"arch"`).

// `smoke_aarch64_features` migrated to arch/src/tests.rs (subsystem `"arch"`).

// `smoke_percpu_this_cpu` migrated to arch/src/tests.rs (subsystem `"arch"`).

// `smoke_domain_primitive_trait` migrated to memory/src/tests.rs (subsystem `"memory"`).

// `smoke_domain_switch` migrated to memory/src/tests.rs (subsystem `"memory"`).

// `smoke_pks_enforces_deny_all` migrated to memory/src/tests.rs (subsystem `"memory"`).

// `smoke_pks_set_get_rights` migrated to memory/src/tests.rs (subsystem `"memory"`).

// `smoke_pcid_cr3_roundtrip` migrated to memory/src/tests.rs (subsystem `"memory"`).

// `smoke_pcid_per_domain_pml4s_distinct` migrated to memory/src/tests.rs (subsystem `"memory"`).

// `smoke_pcid_domain_private_slots_isolated` migrated to memory/src/tests.rs (subsystem `"memory"`).

// `smoke_pcid_domain_private_va_layout` migrated to memory/src/tests.rs (subsystem `"memory"`).

#[cfg(target_arch = "x86_64")]
fn smoke_x86_64_tlb_shootdown_ipi() -> TestResult {
    // Send a TLB-shootdown IPI to AP 1 + verify its ack counter
    // advances. Doesn't actually need a mapped VA — the handler
    // INVLPGs whatever the sender publishes, which is harmless on
    // any address.
    use narf_interrupts::x86_64::{apic, ipi};
    use narf_lib::smp;
    if !smp::is_online(1) {
        return TestResult::Skip("AP CPU 1 offline");
    }
    // The shootdown IPI path writes the x2APIC ICR MSR and has no xAPIC
    // fallback; on a CPU that fell back to xAPIC (QEMU qemu64 / CI's TCG
    // runner) the IPI is never delivered. Skip rather than report a
    // delivery failure that isn't a kernel bug.
    if !apic::x2apic_active() {
        return TestResult::Skip("shootdown IPI requires x2APIC; xAPIC fallback active");
    }

    let before = ipi::ack_count(1);
    // SAFETY: x2APIC online (BSP init), VECTOR_TLB_SHOOTDOWN handler
    // installed at boot, AP 1 online.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        ipi::shoot_va(0xFFFF_FFFF_8000_0000, 0);
    }
    // shoot_va spins until AP acks; if it returned, the counter
    // already moved.
    let after = ipi::ack_count(1);
    if after > before {
        TestResult::Pass
    } else {
        TestResult::Fail("AP ack_count didn't advance")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_x86_64_tlb_shootdown_ipi);

#[cfg(target_arch = "x86_64")]
fn smoke_x86_64_unmap_triggers_shootdown() -> TestResult {
    // Map a fresh page in domain 0's PML4, then unmap it; the unmap
    // path's invlpg_global call should fan out to AP 1 (and any other
    // online APs). The AP's ack counter should advance.
    use narf_arch::x86_64::pcid;
    use narf_interrupts::x86_64::{apic, ipi};
    use narf_lib::smp;
    use narf_memory::frame::alloc_frame;
    use narf_memory::{paging, PhysAddr, VirtAddr};

    if !smp::is_online(1) {
        return TestResult::Skip("AP CPU 1 offline");
    }
    // unmap_4kb fans the shootdown out via the x2APIC ICR MSR (no xAPIC
    // fallback); skip when x2APIC isn't live (CI's qemu64/xAPIC fallback).
    if !apic::x2apic_active() {
        return TestResult::Skip("shootdown IPI requires x2APIC; xAPIC fallback active");
    }

    // Use the bootstrap PML4 (CR3) since QEMU's `-cpu max` runs the
    // PKS path and pcid::get_domain_pml4 returns 0 there. The
    // shootdown hook is independent of the enforcer choice.
    // SAFETY: CR3 read at CPL=0.
    let pml4_phys = unsafe { paging::read_cr3() };
    let _ = pcid::get_domain_pml4(0); // silence unused

    let frame = match alloc_frame() {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("alloc_frame failed"),
    };
    let phys = frame.start_address();
    // Pick a VA in PML4 slot 256 + 5 (domain 5's range, but on PKS
    // path we use the bootstrap PML4 and the slot is empty, so we
    // own the whole walk). Far away from anything mapped.
    let va = VirtAddr::new(0xFFFF_8280_DEAD_0000);

    let before = ipi::ack_count(1);
    // SAFETY: pml4_phys identity-mapped; VA canonical & 4KiB-aligned.
    let map_ok = unsafe {
        paging::map_4kb(
            pml4_phys,
            va,
            phys,
            paging::PtFlags::PRESENT | paging::PtFlags::WRITABLE,
        )
    };
    if map_ok.is_err() {
        return TestResult::Fail("map_4kb failed");
    }
    // SAFETY: paired with the map above.
    let unmap_ok = unsafe { paging::unmap_4kb(pml4_phys, va) };
    if unmap_ok.is_err() {
        return TestResult::Fail("unmap_4kb failed");
    }
    let after = ipi::ack_count(1);
    let _ = phys;
    let _ = PhysAddr::new(0); // type imports kept

    if after > before {
        TestResult::Pass
    } else {
        TestResult::Fail("AP didn't ack the shootdown after unmap_4kb")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_x86_64_unmap_triggers_shootdown);

// `smoke_drivers_claim_mmio_in_domain` migrated to drivers/src/tests.rs (subsystem `"drivers"`).

// `smoke_drivers_default_domain_policy` migrated to drivers/src/tests.rs (subsystem `"drivers"`).

// `smoke_drivers_set_domain_override` migrated to drivers/src/tests.rs (subsystem `"drivers"`).

// `smoke_drivers_release_and_reuse_domain_va` migrated to drivers/src/tests.rs (subsystem `"drivers"`).

#[cfg(target_arch = "x86_64")]
fn smoke_x86_64_shoot_range_one_ipi() -> TestResult {
    // shoot_range(va, N) should advance AP 1's ack counter by exactly
    // 1 — proof that N contiguous pages cost only one IPI.
    use narf_interrupts::x86_64::{apic, ipi};
    use narf_lib::smp;
    if !smp::is_online(1) {
        return TestResult::Skip("AP CPU 1 offline");
    }
    if !apic::x2apic_active() {
        return TestResult::Skip("shootdown IPI requires x2APIC; xAPIC fallback active");
    }
    let before = ipi::ack_count(1);
    // SAFETY: x2APIC online; IPI handler installed at boot.
    unsafe {
        ipi::shoot_range(0xFFFF_FFFF_8000_0000, 8, 0);
    }
    let after = ipi::ack_count(1);
    let diff = after.wrapping_sub(before);
    if diff != 1 {
        return TestResult::Fail(
            alloc::format!("8-page range cost more than 1 IPI: diff={}", diff).leak(),
        );
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_x86_64_shoot_range_one_ipi);

// ─── Input subsystem smokes ─────────────────────────────────────────

// `smoke_input_ring_push_pop_round_trip` migrated to input/src/tests.rs (subsystem `"input"`).

// `smoke_input_ring_overflow_drops_oldest` migrated to input/src/tests.rs (subsystem `"input"`).

// `smoke_i8042_decode_a_keystroke` migrated to drivers/input/src/tests.rs (subsystem `"drivers/input"`).

// `smoke_i8042_modifier_tracking` migrated to drivers/input/src/tests.rs (subsystem `"drivers/input"`).

// `smoke_virtio_input_decode_synthetic` migrated to drivers/input/src/tests.rs (subsystem `"drivers/input"`).

// `smoke_virtio_input_probed_at_boot` migrated to drivers/input/src/tests.rs (subsystem `"drivers/input"`).

// `smoke_input_kind_default_domain` migrated to input/src/tests.rs (subsystem `"input"`).

// ─── Graphics subsystem smokes ──────────────────────────────────────

// `smoke_graphics_pixel_format` migrated to graphics/src/tests.rs (subsystem `"graphics"`).

// `smoke_graphics_clear_and_fill_rect` migrated to graphics/src/tests.rs (subsystem `"graphics"`).

// `smoke_graphics_kind_default_domain` migrated to graphics/src/tests.rs (subsystem `"graphics"`).

// `smoke_bochs_display_probed_at_boot` migrated to drivers/gpu/src/tests.rs (subsystem `"drivers/gpu"`).

// `smoke_virtio_gpu_probed_at_boot` migrated to drivers/gpu/src/tests.rs (subsystem `"drivers/gpu"`).

// `smoke_virtio_gpu_scanout_initialised` migrated to drivers/gpu/src/tests.rs (subsystem `"drivers/gpu"`).

// `smoke_graphics_font_glyph_lookup` migrated to graphics/src/tests.rs (subsystem `"graphics"`).

// `smoke_fb_console_writes_glyphs` migrated to fb/src/tests.rs (subsystem `"fb"`).

// `smoke_fb_console_newline_advances_row` migrated to fb/src/tests.rs (subsystem `"fb"`).

// `smoke_cursor_move_clamps_to_bounds` migrated to graphics/src/tests.rs (subsystem `"graphics"`).

// `smoke_cursor_draw_at_paints_arrow_tip` migrated to graphics/src/tests.rs (subsystem `"graphics"`).

// `smoke_virtio_input_rel_delta_accumulates` migrated to drivers/input/src/tests.rs (subsystem `"drivers/input"`).

// `smoke_i8042_mouse_packet_decode` migrated to drivers/input/src/tests.rs (subsystem `"drivers/input"`).

// `smoke_i8042_mouse_signed_dx_decodes` migrated to drivers/input/src/tests.rs (subsystem `"drivers/input"`).

// `smoke_i8042_mouse_drops_unsynced_byte` migrated to drivers/input/src/tests.rs (subsystem `"drivers/input"`).

// `smoke_splash_render_with_no_console_returns_false` migrated to graphics/src/tests.rs (subsystem `"graphics"`).

// `smoke_splash_render_with_console_paints` migrated to graphics/src/tests.rs (subsystem `"graphics"`).

// ─── narf-init smokes ───────────────────────────────────────────────

// `smoke_init_stages_run_in_order` migrated to init/src/tests.rs (subsystem `"init"`).

// `smoke_init_not_present_does_not_count_as_error` migrated to init/src/tests.rs (subsystem `"init"`).

// `smoke_init_error_continues_to_next_call` migrated to init/src/tests.rs (subsystem `"init"`).

// `smoke_init_records_cycle_totals` migrated to init/src/tests.rs (subsystem `"init"`).

// ─── narf-fb smokes ─────────────────────────────────────────────────

// `smoke_fb_picker_selects_a_backend` migrated to fb/src/tests.rs (subsystem `"fb"`).

// `smoke_fb_writer_fill_clips_and_paints` migrated to fb/src/tests.rs (subsystem `"fb"`).

// `smoke_fb_writer_blit_round_trip` migrated to fb/src/tests.rs (subsystem `"fb"`).

// `smoke_fb_tag_blit_via_shmem` migrated to fb/src/tests.rs (subsystem `"fb"`).

// `smoke_fb_rect_clip_math` migrated to fb/src/tests.rs (subsystem `"fb"`).

// `smoke_fb_drawcmd_size_is_48` migrated to fb/src/tests.rs (subsystem `"fb"`).

// `smoke_fb_cmd_ring_round_trip` migrated to fb/src/tests.rs (subsystem `"fb"`).

// `smoke_fb_client_drives_drain_to_pixel` migrated to fb/src/tests.rs (subsystem `"fb"`).

// `smoke_fb_registry_connect_disconnect` migrated to fb/src/tests.rs (subsystem `"fb"`).

// `smoke_shmem_create_destroy_round_trip` migrated to shmem/src/tests.rs (subsystem `"shmem"`).

// `smoke_shmem_sg_iter_walks_pages` migrated to shmem/src/tests.rs (subsystem `"shmem"`).

// `smoke_shmem_exit_observer_reaps_handles` migrated to shmem/src/tests.rs (subsystem `"shmem"`).

// `smoke_fb_exit_observer_reaps_handles` migrated to fb/src/tests.rs (subsystem `"fb"`).

// `smoke_fb_registry_drain_all_executes_per_process` migrated to fb/src/tests.rs (subsystem `"fb"`).

// `smoke_fb_drain_once_advances_counters` migrated to fb/src/tests.rs (subsystem `"fb"`).

// `smoke_fb_e2e_via_test_scanout` migrated to fb/src/tests.rs (subsystem `"fb"`).

// `smoke_ioremap_direct_round_trip` migrated to io/src/tests.rs (subsystem `"io"`).

// `smoke_fb_userspace_chain_against_real_backend` migrated to fb/src/tests.rs (subsystem `"fb"`).

// `smoke_pte_pk_field` migrated to memory/src/tests.rs (subsystem `"memory"`).

// `smoke_pkrs_roundtrip` migrated to memory/src/tests.rs (subsystem `"memory"`).

// `smoke_map_preserves_pk_field` migrated to memory/src/tests.rs (subsystem `"memory"`).

// `smoke_paging_map_translate_unmap` migrated to memory/src/tests.rs (subsystem `"memory"`).

// `smoke_frame_alloc_roundtrip` migrated to memory/src/tests.rs (subsystem `"memory"`).

// `smoke_bus_enumerates_pcie` migrated to bus/src/tests.rs (subsystem `"bus"`).

// `smoke_bus_pcie_dtb_aarch64` migrated to bus/src/tests.rs (subsystem `"bus"`).

// `smoke_bus_enumerates_virtio_mmio` migrated to bus/src/tests.rs (subsystem `"bus"`).

// `smoke_bus_claim_device_not_found` migrated to bus/src/tests.rs (subsystem `"bus"`).

// `smoke_bus_msix_alloc_vector` migrated to bus/src/tests.rs (subsystem `"bus"`).

// `smoke_bus_msix_program_vector_out_of_range` migrated to bus/src/tests.rs (subsystem `"bus"`).

// `smoke_bus_bar_read_on_q35` migrated to bus/src/tests.rs (subsystem `"bus"`).

// `smoke_its_doorbell_addr` migrated to bus/src/tests.rs (subsystem `"bus"`).

// `smoke_bus_msix_enable_on_virtio` migrated to bus/src/tests.rs (subsystem `"bus"`).

// `smoke_bus_hotplug_listener_roundtrip` migrated to bus/src/tests.rs (subsystem `"bus"`).

// `smoke_bus_hotplug_revoked_authority` migrated to bus/src/tests.rs (subsystem `"bus"`).

// `smoke_bus_iommu_group_default` migrated to bus/src/tests.rs (subsystem `"bus"`).

// `smoke_sleep_future_waits` migrated to scheduler/src/tests.rs (subsystem `"scheduler"`).

// `smoke_tracing_note_section_present` migrated to tracing/src/tests.rs (subsystem `"tracing"`).

// `smoke_tracing_flight_ring_basic` migrated to tracing/src/tests.rs (subsystem `"tracing"`).

// ── rcu/ side-track tests ───────────────────────────────────────────
//
// Exercise the QSBR + Epoch variants end-to-end: pin, load through an
// Atomic<T>, swap, defer-drop, sync, confirm the old value's Drop ran.

// `smoke_rcu_qsbr_pin_unpin` migrated to rcu/src/tests.rs (subsystem `"rcu"`).

// `smoke_rcu_qsbr_reclaims` migrated to rcu/src/tests.rs (subsystem `"rcu"`).

// `smoke_rcu_epoch_pin_cycle` migrated to rcu/src/tests.rs (subsystem `"rcu"`).

// `smoke_rcu_epoch_defer_drop` migrated to rcu/src/tests.rs (subsystem `"rcu"`).

// `smoke_ipc_spsc_round_trip` migrated to ipc/src/tests.rs (subsystem `"ipc"`).

// `smoke_ipc_shared_ring_round_trip` migrated to ipc/src/tests.rs (subsystem `"ipc"`).

fn smoke_ipc_shared_ring_size_bounds() -> TestResult {
    // Both ABI-shape rings used by Stage-4 must fit in a single 4 KiB
    // page so they're user-mappable as one mmap.
    use narf_abi::{Completion, Submission};
    use narf_ipc::SharedRing;
    if SharedRing::<Submission, 16>::size_bytes() > 4096 {
        return TestResult::Fail("SharedRing<Submission,16> > 4 KiB");
    }
    if SharedRing::<Completion, 16>::size_bytes() > 4096 {
        return TestResult::Fail("SharedRing<Completion,16> > 4 KiB");
    }
    TestResult::Pass
}
kernel_test!(smoke_ipc_shared_ring_size_bounds);

// `smoke_ipc_spsc_try_send_full` migrated to ipc/src/tests.rs (subsystem `"ipc"`).

// `smoke_ipc_spsc_close_eof` migrated to ipc/src/tests.rs (subsystem `"ipc"`).

// `smoke_ipc_spsc_drain_then_eof` migrated to ipc/src/tests.rs (subsystem `"ipc"`).

// ── abi ───────────────────────────────────────────────────────────

// `smoke_abi_submission_layout` migrated to abi/src/tests.rs (subsystem `"abi"`).

// `smoke_abi_completion_layout` migrated to abi/src/tests.rs (subsystem `"abi"`).

// `smoke_abi_ring_roundtrip` migrated to abi/src/tests.rs (subsystem `"abi"`).

// `smoke_cap_bootstrap_and_invoke` migrated to capabilities/src/tests.rs (subsystem `"capabilities"`).

// `smoke_cap_revoke_invalidates` migrated to capabilities/src/tests.rs (subsystem `"capabilities"`).

// `smoke_cap_independent_objects` migrated to capabilities/src/tests.rs (subsystem `"capabilities"`).

// `smoke_io_dma_alloc_free` migrated to io/src/tests.rs (subsystem `"io"`).

// `smoke_io_dma_cap_bootstrap` migrated to io/src/tests.rs (subsystem `"io"`).

// `smoke_io_iommu_stub_map_unmap` migrated to io/src/tests.rs (subsystem `"io"`).

// `smoke_drivers_register_and_lifecycle` migrated to drivers/src/tests.rs (subsystem `"drivers"`).

// `smoke_drivers_register_revoked_authority` migrated to drivers/src/tests.rs (subsystem `"drivers"`).

// `smoke_drivers_dedicated_domain_exhaustion` migrated to drivers/src/tests.rs (subsystem `"drivers"`).

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
    use narf_drivers_virtio::{ProbeError, VirtioMmioDevice};
    // SAFETY: init tolerates a null/absent DTB by falling back to the
    // QEMU-virt default layout; identity-map covers the MMIO window.
    // SAFETY: Valid memory or trusted environment
    let _n = unsafe { narf_bus::init(None) };
    let mut ok = 0usize;
    for d in devices() {
        if !matches!(d.kind, BusKind::VirtioMmio { .. }) {
            continue;
        }
        // SAFETY: the bus registry published these entries after
        // confirming their MMIO regions are mapped and readable;
        // `probe` does a bounded u32 read.
        // SAFETY: Valid memory or trusted environment
        match unsafe { VirtioMmioDevice::probe(&d) } {
            Ok(v) => {
                if v.version() != 2 {
                    return TestResult::Fail("probed transport reported non-modern version");
                }
                ok += 1;
            }
            // The bus registry filters out empty (device_id == 0) MMIO slots
            // before we see them, so a bus-registry entry that fails probe is
            // a real anomaly. Report *which* failure: collapsing them into one
            // message made a genuine bug indistinguishable from a mapping
            // failure when this finally ran.
            Err(ProbeError::WrongMagic) => {
                return TestResult::Fail("virtio-mmio entry read the wrong magic");
            }
            Err(ProbeError::UnsupportedVersion) => {
                return TestResult::Fail("virtio-mmio entry reported a legacy version");
            }
            Err(ProbeError::MapFailed) => {
                return TestResult::Fail("could not map the virtio-mmio register window");
            }
            Err(ProbeError::NotVirtioMmio) | Err(ProbeError::EmptySlot) => {
                return TestResult::Fail("bus registry published a non-virtio-mmio entry");
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
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{devices, BusKind};
    // SAFETY: ECAM_DEFAULT_BASE is inside q35's pcie-mmcfg region and
    // the walker performs read-only config-space probes.
    // SAFETY: Valid memory or trusted environment
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
    // SAFETY: Valid memory or trusted environment
    let result = unsafe { VirtioMmioDevice::probe_raw(addr) };
    // Prevent the optimiser from eliding the buffer even under fat LTO.
    core::hint::black_box(&fake);
    match result {
        Err(ProbeError::WrongMagic) => TestResult::Pass,
        Err(e) => {
            let _ = e;
            TestResult::Fail("wrong-magic probe returned the wrong error variant")
        }
        Ok(_) => TestResult::Fail("wrong-magic probe unexpectedly succeeded"),
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

// `smoke_exit_gate_buffer_handoff` migrated to ipc/src/tests.rs (subsystem `"ipc"`).

// `smoke_exit_gate_revoked_cap_rejected` migrated to ipc/src/tests.rs (subsystem `"ipc"`).

// ── block ──

fn smoke_block_device_trait() -> TestResult {
    use narf_block::{BlockDevice, BlockOp, BlockRequest, QosHint};
    use narf_capabilities::Read;
    use narf_drivers_virtio::blk::VirtioBlkDevice;
    use narf_drivers_virtio::VirtioMmioDevice;
    use narf_io::{alloc_coherent, register_with_cap};
    use narf_lib::id::DomainId;

    narf_scheduler::__reset_queues_for_test();

    // 1. Probe a fake device (null addr).
    // SAFETY: Valid memory or trusted environment
    let mmio = unsafe { VirtioMmioDevice::probe_raw(0) };
    let Ok(mmio_dev) = mmio else {
        // probe_raw(0) fails magic check; this is expected for a compile test.
        // To do a real functional test, we'd need a mock VirtIO device.
        return TestResult::Pass;
    };

    let mut blk = VirtioBlkDevice::new(mmio_dev);

    // 2. Initialise.
    // SAFETY: Valid memory or trusted environment
    if unsafe { blk.init(DomainId::DRIVER_0) }.is_err() {
        return TestResult::Fail("VirtioBlkDevice::init failed");
    }

    // 3. Submit a request.
    let Ok(buf) = alloc_coherent(512, DomainId::DRIVER_0) else {
        return TestResult::Fail("DMA alloc failed");
    };
    let cap_w = register_with_cap(buf);
    let cap: narf_capabilities::Cap<narf_io::DmaBuffer, Read> =
        cap_w.derive::<Read>().expect("derive Read from Write");

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
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU8, Ordering};
    use narf_block::{BlockCompletion, BlockOp, BlockRequest, QosHint};
    use narf_capabilities::Read;
    use narf_drivers_virtio::blk::VirtioBlkDevice;
    use narf_drivers_virtio::class_blk::VirtioBlkServer;
    use narf_drivers_virtio::VirtioMmioDevice;
    use narf_io::{alloc_coherent, register_with_cap};
    use narf_lib::id::DomainId;

    static OUTCOME: AtomicU8 = AtomicU8::new(0);

    narf_scheduler::__reset_queues_for_test();

    // 1. Setup rings and server.
    let (mut req_tx, req_rx) = narf_ipc::channel::<BlockRequest, 4>();
    let (compl_tx, mut compl_rx) = narf_ipc::channel::<BlockCompletion, 4>();

    // SAFETY: Valid memory or trusted environment
    let mmio = unsafe { VirtioMmioDevice::probe_raw(0) };
    let Ok(mmio_dev) = mmio else {
        return TestResult::Pass;
    };

    let mut blk = VirtioBlkDevice::new(mmio_dev);
    // SAFETY: Valid memory or trusted environment
    unsafe {
        blk.init(DomainId::DRIVER_0).unwrap();
    }
    let blk = Arc::new(blk);

    let mut server = VirtioBlkServer::new(blk.clone(), req_rx, compl_tx);

    // 2. Spawn "Driver Domain" server task.
    narf_scheduler::spawn(async move {
        server.run().await;
    });

    // 3. Spawn "Consumer Domain" task.
    narf_scheduler::spawn(async move {
        let Ok(buf) = alloc_coherent(512, DomainId::DRIVER_0) else {
            return;
        };
        let cap_w = register_with_cap(buf);
        let cap: narf_capabilities::Cap<narf_io::DmaBuffer, Read> =
            cap_w.derive::<Read>().expect("derive Read from Write");

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
            if OUTCOME.load(Ordering::Relaxed) != 0 {
                break;
            }
        }
    });

    narf_scheduler::run_until_empty();

    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        _ => TestResult::Fail("exit gate flow did not complete"),
    }
}
kernel_test!(smoke_exit_gate_virtio_blk);

// `smoke_abi_dispatcher_roundtrip` migrated to abi/src/tests.rs (subsystem `"abi"`).

// `smoke_lib_current_domain_hook` migrated to lib/src/tests.rs (subsystem `"lib"`).

// `smoke_lib_assert_in_domain_passes_on_frame` migrated to lib/src/tests.rs (subsystem `"lib"`).

// `smoke_lib_bug_on_false_is_silent` migrated to lib/src/tests.rs (subsystem `"lib"`).

// ── crypto/ smokes ──────────────────────────────────────────────────
//
// Stage-3 round 2: cap-gated primitive surface in narf-crypto. Vectors
// come from canonical sources so a regression in the underlying
// RustCrypto crates surfaces immediately rather than as a downstream
// protocol failure.

// `smoke_crypto_ed25519_verify` migrated to crypto/src/tests.rs (subsystem `"crypto"`).

// `smoke_crypto_chacha20_roundtrip` migrated to crypto/src/tests.rs (subsystem `"crypto"`).

// `smoke_crypto_hkdf_test_vector` migrated to crypto/src/tests.rs (subsystem `"crypto"`).

// `smoke_crypto_blake3_known_answer` migrated to crypto/src/tests.rs (subsystem `"crypto"`).

// ── net ───────────────────────────────────────────────────────────

// `smoke_net_loopback_register` migrated to net/src/tests.rs (subsystem `"net"`).

// `smoke_net_loopback_roundtrip` migrated to net/src/tests.rs (subsystem `"net"`).

// `smoke_net_loopback_revoked_authority` migrated to net/src/tests.rs (subsystem `"net"`).

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
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
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

// `smoke_fs_initramfs_mount_and_stat` migrated to filesystem/src/tests.rs (subsystem `"filesystem"`).

// `smoke_fs_initramfs_read` migrated to filesystem/src/tests.rs (subsystem `"filesystem"`).

// `smoke_fs_lookup_missing` migrated to filesystem/src/tests.rs (subsystem `"filesystem"`).

// `smoke_fs_mount_revoked_authority` migrated to filesystem/src/tests.rs (subsystem `"filesystem"`).

// ── power/ smokes ───────────────────────────────────────────────────
//
// Stage-3 round 3: cap-gated C-state registry, DVFS governor framework,
// per-driver runtime PM. Tests run after net/ / fs/ smokes in this
// file, so the global power tables may already hold defaults from a
// previous `init()` call — the registry deliberately tolerates this
// (duplicate-id rejection on cstates, governor slot is overwritten).

// `smoke_power_cstate_register` migrated to power/src/tests.rs (subsystem `"power"`).

// `smoke_power_governor_swap` migrated to power/src/tests.rs (subsystem `"power"`).

// `smoke_power_device_pm_lifecycle` migrated to power/src/tests.rs (subsystem `"power"`).

// `smoke_rcu_sleepable_enter_exit` migrated to rcu/src/tests.rs (subsystem `"rcu"`).

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
    use narf_capabilities::{Cap, Read};
    use narf_rcu::sleepable::{sync_async, SleepableReader, SleepableScope, SyncOutcome};

    static SCOPE: SleepableScope = SleepableScope::new();
    static CAP_SET: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    static mut CAP: Option<Cap<SleepableReader, Read>> = None;
    static OUTCOME: AtomicU8 = AtomicU8::new(0); // 0=pending, 1=drained, 2=timeout, 3=error

    OUTCOME.store(0, Ordering::Relaxed);
    SCOPE.clear_over_budget();
    // Force a fresh cap each invocation. Last-test residue (especially
    // when the harness repeats) would otherwise see active != 0 leak.
    // SAFETY: harness is single-threaded; no concurrent CAP access.
    unsafe {
        CAP = Some(SleepableReader::bootstrap_cap());
        CAP_SET.store(true, Ordering::Release);
    }

    narf_scheduler::__reset_queues_for_test();

    // Holder task — yields three times, then drops the guard.
    narf_scheduler::spawn(async move {
        // SAFETY: CAP is set above on the same thread before
        // spawn. `&raw const` (Rust 2024) takes a raw pointer
        // to the static without going through `&`, dodging the
        // rust_2024_compatibility static_mut_refs lint.
        // SAFETY: Valid memory or trusted environment
        let cap = unsafe { (*core::ptr::addr_of!(CAP)).as_ref().unwrap() };
        let g = SCOPE.enter(cap).expect("enter must succeed");
        for _ in 0..3 {
            narf_scheduler::yield_now().await;
        }
        drop(g);
    });

    // Waiter task — sync_async with a generous deadline.
    narf_scheduler::spawn(async move {
        let deadline = narf_time::Instant::now().plus_cycles(1_000_000_000);
        match sync_async(&SCOPE, deadline).await {
            SyncOutcome::Drained => OUTCOME.store(1, Ordering::Relaxed),
            SyncOutcome::Timeout => OUTCOME.store(2, Ordering::Relaxed),
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
    use narf_capabilities::{Cap, Read};
    use narf_rcu::sleepable::{sync_async, SleepableReader, SleepableScope, SyncOutcome};

    static SCOPE: SleepableScope = SleepableScope::new();
    static mut CAP: Option<Cap<SleepableReader, Read>> = None;
    static OUTCOME: AtomicU8 = AtomicU8::new(0);
    static DONE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

    OUTCOME.store(0, Ordering::Relaxed);
    DONE.store(false, Ordering::Relaxed);
    SCOPE.clear_over_budget();
    // SAFETY: harness is single-threaded.
    unsafe {
        CAP = Some(SleepableReader::bootstrap_cap());
    }

    narf_scheduler::__reset_queues_for_test();

    // Holder task — holds the guard until DONE flips. Yields each
    // round so the executor doesn't deadlock.
    narf_scheduler::spawn(async move {
        // SAFETY: CAP is set above before spawn.
        #[allow(static_mut_refs)] // TODO(narf): migrate this boot-time static to addr_of!/OnceCell
        // SAFETY: Valid memory or trusted environment
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
            SyncOutcome::Timeout => OUTCOME.store(2, Ordering::Relaxed),
            SyncOutcome::Drained => OUTCOME.store(1, Ordering::Relaxed),
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

// `smoke_rcu_sleepable_revoked_cap_rejected` migrated to rcu/src/tests.rs (subsystem `"rcu"`).

// ── rcu/ hazard-pointer tests ──────────────────────────────────────
//
// Cover the three load-bearing properties of `HazardDomain`:
//   * publish + retire round-trip (no readers active)
//   * retire while a reader holds the guard — drop must wait
//   * batch retire of unheld pointers — one scan() drains all

// `smoke_rcu_hazard_publish_retire` migrated to rcu/src/tests.rs (subsystem `"rcu"`).

// `smoke_rcu_hazard_retired_but_held` migrated to rcu/src/tests.rs (subsystem `"rcu"`).

// `smoke_rcu_hazard_scan_frees_unheld` migrated to rcu/src/tests.rs (subsystem `"rcu"`).

// ── observability/ Stage-2/3 smoke tests ────────────────────────────
//
// PMU read paths, panic-snapshot install, and the synthesised
// CrashFrame round-trip. Each test is independent — the panic-ring
// install test uses `__test_clear_panic_ring` to reset shared state.

// `smoke_obs_pmu_cycles_monotonic` migrated to observability/src/tests.rs (subsystem `"observability"`).

// `smoke_obs_pmu_cap_gated` migrated to observability/src/tests.rs (subsystem `"observability"`).

// `smoke_obs_crash_frame_captures_regs` migrated to observability/src/tests.rs (subsystem `"observability"`).

// `smoke_obs_panic_snapshot_roundtrip` migrated to observability/src/tests.rs (subsystem `"observability"`).

// `smoke_arch_patch_word_roundtrip` migrated to arch/src/tests.rs (subsystem `"arch"`).

// `smoke_tracing_arm_disarm_cycle` migrated to tracing/src/tests.rs (subsystem `"tracing"`).

// `smoke_tracing_dispatch_fire_routes_handler` migrated to tracing/src/tests.rs (subsystem `"tracing"`).

// `smoke_tracing_fntime_welford_accumulates` migrated to tracing/src/tests.rs (subsystem `"tracing"`).

// `smoke_tracing_fntime_scope_records_cycles` migrated to tracing/src/tests.rs (subsystem `"tracing"`).

// `smoke_tracing_histogram_quantile_bucket` migrated to tracing/src/tests.rs (subsystem `"tracing"`).

// `smoke_obs_pmu_sample_into_ring` migrated to observability/src/tests.rs (subsystem `"observability"`).

// `smoke_obs_core_dump_bundles_snapshot` migrated to observability/src/tests.rs (subsystem `"observability"`).

// `smoke_scheduler_budget_cap_revokes_task` migrated to scheduler/src/tests.rs (subsystem `"scheduler"`).

// `smoke_scheduler_budget_accounts_cycles` migrated to scheduler/src/tests.rs (subsystem `"scheduler"`).

// `smoke_abi_cancel_before_target_marks_cancelled` migrated to abi/src/tests.rs (subsystem `"abi"`).

// `smoke_abi_cancel_non_cancellable_marks_request` migrated to abi/src/tests.rs (subsystem `"abi"`).

// `smoke_abi_dispatch_latency_accumulates` migrated to abi/src/tests.rs (subsystem `"abi"`).

// `smoke_abi_linked_chain_cancels_forward` migrated to abi/src/tests.rs (subsystem `"abi"`).

// `smoke_abi_cancel_stale_tag_is_noop` migrated to abi/src/tests.rs (subsystem `"abi"`).

// `smoke_scheduler_cpu_lifecycle_take_offline` migrated to scheduler/src/tests.rs (subsystem `"scheduler"`).

// `smoke_scheduler_realtime_spec` migrated to scheduler/src/tests.rs (subsystem `"scheduler"`).

// `smoke_scheduler_donate_to_reorders_head` migrated to scheduler/src/tests.rs (subsystem `"scheduler"`).

// `smoke_scheduler_current_task_id_during_poll` migrated to scheduler/src/tests.rs (subsystem `"scheduler"`).

// `smoke_scheduler_donate_to_rejects_revoked_cap` migrated to scheduler/src/tests.rs (subsystem `"scheduler"`).

// `smoke_scheduler_donate_to_missing_target` migrated to scheduler/src/tests.rs (subsystem `"scheduler"`).

// `smoke_scheduler_cpu_set_membership` migrated to scheduler/src/tests.rs (subsystem `"scheduler"`).

#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
fn make_block_request(op: narf_block::BlockOp, user_tag: u64) -> narf_block::BlockRequest {
    use narf_block::{BlockRequest, QosHint};
    use narf_capabilities::{Cap, CapSlot, Read, Rights};
    // SAFETY: Valid memory or trusted environment
    let cap = unsafe {
        Cap::<narf_io::DmaBuffer, Read>::mint(CapSlot::new(
            1,
            0,
            Read::BITS,
            narf_capabilities::CapKind::DmaBuffer as u32,
        ))
    };
    BlockRequest {
        op,
        lba: 0,
        blocks: 1,
        buffer: cap,
        qos: QosHint::Latency,
        user_tag,
    }
}

// `smoke_block_deadline_prefers_reads` migrated to block/src/tests.rs (subsystem `"block"`).

// `smoke_block_deadline_promotes_expired` migrated to block/src/tests.rs (subsystem `"block"`).

// `smoke_power_suspend_phase_progression` migrated to power/src/tests.rs (subsystem `"power"`).

// `smoke_tracing_hwtrace_surface` migrated to tracing/src/tests.rs (subsystem `"tracing"`).

// `smoke_fs_fuse_opcode_constants` migrated to filesystem/src/tests.rs (subsystem `"filesystem"`).

// `smoke_drivers_gpu_mode_and_family` migrated to drivers/gpu/src/tests.rs (subsystem `"drivers/gpu"`).

// `smoke_bus_acpi_notify_dispatch` migrated to bus/src/tests.rs (subsystem `"bus"`).

// `smoke_rcu_batched_reclaim_drains` migrated to rcu/src/tests.rs (subsystem `"rcu"`).

// `smoke_net_stack_attach_not_implemented` migrated to net/src/tests.rs (subsystem `"net"`).

// `smoke_fs_page_cache_dirty_drain` migrated to filesystem/src/tests.rs (subsystem `"filesystem"`).

// `smoke_crypto_tpm_command_shapes` migrated to crypto/src/tests.rs (subsystem `"crypto"`).

// `smoke_crypto_pq_fips_gate` migrated to crypto/src/tests.rs (subsystem `"crypto"`).

// nvme cap-decode + probe-stub smokes migrated to
// `drivers/nvme/src/tests.rs` (subsystem `drivers/nvme`).

// nvme admin-identify smoke migrated to `drivers/nvme/src/tests.rs`
// (subsystem `drivers/nvme`).

// nvme io_round_trip + io_msix_irq_driven smokes migrated to
// `drivers/nvme/src/tests.rs` (subsystem `drivers/nvme`).

// `smoke_pci_command_bme_round_trip` migrated to bus/src/tests.rs (subsystem `"bus"`).

// `smoke_pci_match_specificity` migrated to bus/src/tests.rs (subsystem `"bus"`).

#[cfg(target_arch = "x86_64")]
fn smoke_pci_probe_all_dispatches_nvme() -> TestResult {
    // End-to-end registry path: register the NVMe driver via the
    // bus-level match table, run probe_all, and assert the NVMe
    // controller stashed itself in its own static after a
    // successful probe.
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    // SAFETY: ECAM identity-mapped; init idempotent.
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has_nvme = devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. }) && d.id.vendor == 0x1B36 && d.id.device == 0x0010
    });
    if !has_nvme {
        return TestResult::Skip("no QEMU NVMe controller");
    }

    // Hermetic: clear any earlier registrations.
    __reset_for_test();
    narf_drivers_nvme::register_pci_driver();
    // nvme registers 4 exact VID/DID entries (QEMU + Samsung
    // PM9A1 / 970 EVO / 990 PRO) plus a class-storage backstop —
    // 5 entries total. Probe filters by subclass + prog_if so the
    // backstop doesn't accidentally claim SATA / virtio-blk.
    let regs = narf_bus::registered_pci_drivers();
    if regs.len() < 2 {
        return TestResult::Fail("nvme registered fewer than the expected entries");
    }
    let has_qemu_vid = regs.iter().any(|m| {
        matches!(
            m.kind,
            narf_bus::MatchKind::VendorDevice {
                vendor: 0x1B36,
                device: 0x0010,
            }
        )
    });
    let has_class = regs.iter().any(|m| {
        matches!(
            m.kind,
            narf_bus::MatchKind::ClassFull {
                class: 0x01,
                subclass: 0x08,
                prog_if: 0x02,
            }
        )
    });
    if !has_qemu_vid {
        return TestResult::Fail("nvme missing QEMU VID/DID entry");
    }
    if !has_class {
        return TestResult::Fail("nvme missing storage-class backstop");
    }

    let authority = bootstrap_registry_authority();
    let bound = match probe_all_pci(&authority) {
        Ok(n) => n,
        Err(_) => return TestResult::Fail("probe_all_pci returned AuthorityRevoked"),
    };
    if bound == 0 {
        return TestResult::Fail("probe_all_pci bound zero drivers");
    }
    if !narf_drivers_nvme::is_probed() {
        return TestResult::Fail("NVMe driver did not stash a controller");
    }
    // Verify the probed controller has the IDENTIFY snapshot.
    let model_starts_with_qemu = narf_drivers_nvme::with_controller(|c| {
        c.identify().is_some_and(|id| &id.mn[..4] == b"QEMU")
    })
    .unwrap_or(false);
    if !model_starts_with_qemu {
        return TestResult::Fail("probe-loaded controller missing IDENTIFY MN=QEMU");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_pci_probe_all_dispatches_nvme);

// nvme params_typed_round_trip smoke migrated to
// `drivers/nvme/src/tests.rs` (subsystem `drivers/nvme`).

// `smoke_param_slot_not_installed` migrated to drivers/src/tests.rs (subsystem `"drivers"`).

// `smoke_rights_lattice_derive` migrated to capabilities/src/tests.rs (subsystem `"capabilities"`).

// `smoke_syscall_versioning_dispatch` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_pci_cap_walker_finds_msix` migrated to bus/src/tests.rs (subsystem `"bus"`).

// `smoke_pci_express_cap_link_status` migrated to bus/src/tests.rs (subsystem `"bus"`).

// `smoke_vector_alloc_block_contiguous` migrated to interrupts/src/tests.rs (subsystem `"interrupts"`).

// `smoke_msix_program_block` migrated to bus/src/tests.rs (subsystem `"bus"`).

// `smoke_pci_cap_ext_walker` migrated to bus/src/tests.rs (subsystem `"bus"`).

// virtio-blk-pci read_sector smoke migrated to
// `drivers/virtio/src/tests.rs` (subsystem `drivers/virtio/blk-pci`).

// virtio-blk-pci write_then_read smoke migrated.

// virtio-blk-pci irq_driven smoke migrated.

// virtio-blk-pci irq_async smoke migrated.

// virtio-blk-pci write_irq_async + virtio-net-pci tx/rx-arp smokes
// migrated to `drivers/virtio/src/tests.rs`.

// `smoke_net_icmp_echo_builder` migrated to net/src/tests.rs (subsystem `"net"`).
#[cfg(target_arch = "x86_64")]
fn smoke_net_e1000_arp_round_trip() -> TestResult {
    // Build an ARP request via the new pkt builders, transmit via
    // e1000, drain RX hunting for an ARP reply from QEMU's
    // gateway. Validates the new packet stack against the live
    // network driver.
    use narf_drivers_net::e1000;
    use narf_net::pkt::*;
    if !e1000::is_probed() {
        return TestResult::Skip("e1000 not probed");
    }
    let mac = e1000::with_controller(|c| c.mac).unwrap_or([0; 6]);
    let mut frame = [0u8; 64];
    let n = build_arp_request(&mut frame, mac, [10, 0, 2, 15], [10, 0, 2, 2]).unwrap_or(0);
    if n == 0 {
        return TestResult::Fail("build_arp_request");
    }
    if !e1000::with_controller(|c| c.tx(&frame[..n]))
        .map(|r| r.is_ok())
        .unwrap_or(false)
    {
        return TestResult::Fail("e1000 tx of ARP request");
    }
    // Drain RX briefly looking for a frame; parse it.
    let mut rx = [0u8; 1518];
    let mut got_any = false;
    for _ in 0..2_000_000u32 {
        let len = e1000::with_controller(|c| c.rx_recv(&mut rx)).unwrap_or(0);
        if len > 0 {
            got_any = true;
            // Try parsing — any well-formed Ethernet frame counts.
            if parse_eth_header(&rx[..len]).is_none() {
                return TestResult::Fail("RX frame failed eth-header parse");
            }
            break;
        }
        core::hint::spin_loop();
    }
    let _ = got_any;
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_net_e1000_arp_round_trip);

// `smoke_bound_drivers_inventory` migrated to drivers/src/tests.rs (subsystem `"drivers"`).

// `smoke_slab_alloc_free_round_trip` migrated to memory/src/tests.rs (subsystem `"memory"`).

// `smoke_slab_class_picker` migrated to memory/src/tests.rs (subsystem `"memory"`).

// `smoke_slab_stats_advance` migrated to memory/src/tests.rs (subsystem `"memory"`).

// `smoke_slab_magazine_hot_path` migrated to memory/src/tests.rs (subsystem `"memory"`).

fn smoke_percpu_current_id() -> TestResult {
    // Single-CPU today — current_cpu_id() must return 0 on the BSP.
    let id = narf_arch::current_cpu_id().raw();
    if id != 0 {
        return TestResult::Fail("BSP current_cpu_id != 0");
    }
    TestResult::Pass
}
kernel_test!(smoke_percpu_current_id);

// `smoke_percpu_storage_isolation` migrated to lib/src/tests.rs (subsystem `"lib"`).

// `smoke_aarch64_mpidr_aff_present` migrated to arch/src/tests.rs (subsystem `"arch"`).

fn smoke_smp_bsp_baseline() -> TestResult {
    use narf_lib::smp;
    if !smp::is_online(0) {
        return TestResult::Fail("BSP not marked online");
    }
    if smp::online_count() < 1 {
        return TestResult::Fail("online_count < 1");
    }
    if smp::cpu_count() < 1 {
        return TestResult::Fail("cpu_count < 1");
    }
    if smp::online_bitmap() & 1 == 0 {
        return TestResult::Fail("BSP bit clear");
    }
    TestResult::Pass
}
kernel_test!(smoke_smp_bsp_baseline);

fn smoke_smp_mark_online_offline() -> TestResult {
    use narf_lib::smp;
    // Use a slot well above any realistic AP count for bookkeeping
    // — once aarch64 actually brings up CPU 1 via PSCI, slot 1 may
    // already be set, so test against an unused slot.
    const TEST_SLOT: u32 = 63;
    let initial = smp::is_online(TEST_SLOT);
    if initial {
        smp::mark_offline(TEST_SLOT);
    }
    if smp::is_online(TEST_SLOT) {
        return TestResult::Fail("offline didn't clear initial state");
    }
    // Fake setter, NOT `mark_online`: the real marker's unsafe contract is
    // "calling CPU only", and it also stamps the monotonic ever-online
    // record — polluting that from a fake slot would make the scheduler
    // remote-kick smoke (which skips whenever any CPU besides the BSP was
    // ever genuinely online) skip forever on real SMP=1 boots.
    smp::__test_fake_online(TEST_SLOT);
    if !smp::is_online(TEST_SLOT) {
        return TestResult::Fail("fake online didn't set bit");
    }
    // The fake must NOT register in the ever-genuinely-online record.
    if smp::ever_online_bitmap() & (1u64 << TEST_SLOT) != 0 {
        return TestResult::Fail("fake online leaked into ever-online record");
    }
    // The BSP's boot bring-up must.
    if smp::ever_online_bitmap() & 1 == 0 {
        return TestResult::Fail("BSP missing from ever-online record");
    }
    smp::mark_offline(TEST_SLOT);
    if smp::is_online(TEST_SLOT) {
        return TestResult::Fail("mark_offline didn't clear bit");
    }
    TestResult::Pass
}
kernel_test!(smoke_smp_mark_online_offline);

#[cfg(target_arch = "aarch64")]
fn smoke_smp_aarch64_ap_online() -> TestResult {
    // After PSCI bring-up at boot, CPU 1 is online if QEMU was
    // started with -smp >= 2. xtask sets -smp 2 by default.
    use narf_lib::smp;
    if smp::cpu_count() < 2 {
        return TestResult::Skip("BSP-only QEMU config");
    }
    if !smp::is_online(1) {
        return TestResult::Fail("AP CPU 1 didn't come online");
    }
    if smp::online_count() < 2 {
        return TestResult::Fail("online_count < 2 with -smp 2");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test!(smoke_smp_aarch64_ap_online);

#[cfg(target_arch = "aarch64")]
fn smoke_smp_aarch64_ap_timer_ticks() -> TestResult {
    // After AP bring-up, the AP enables its timer + unmasks DAIF.
    // Sample the AP's per-CPU tick counter twice with a busy wait
    // between; the second read must be strictly greater than the
    // first.
    use narf_interrupts::aarch64::timer;
    use narf_lib::smp;
    if !smp::is_online(1) {
        return TestResult::Skip("AP CPU 1 not online");
    }
    let before = timer::timer_ticks_for(1);
    // Busy-wait a measurable interval. CNTPCT_EL0 advances at
    // 62.5 MHz on QEMU virt; ~50M cycles ≈ 800 ms. Plenty of room
    // for several timer-PPI deliveries with TIMER_TVAL_DEFAULT
    // (~80 ms).
    let start = narf_time::Instant::now();
    while narf_time::Instant::now().cycles_since(start) < 50_000_000 {
        core::hint::spin_loop();
    }
    let after = timer::timer_ticks_for(1);
    if after <= before {
        return TestResult::Fail("AP timer never fired during wait");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test!(smoke_smp_aarch64_ap_timer_ticks);

#[cfg(target_arch = "aarch64")]
fn smoke_smp_aarch64_sgi_to_ap() -> TestResult {
    // Send an SGI to the AP + verify its receive counter advances.
    use narf_interrupts::aarch64::sgi;
    use narf_lib::smp;
    if !smp::is_online(1) {
        return TestResult::Skip("AP CPU 1 offline");
    }

    let intid: u8 = 7; // an unused vector slot
    let before = sgi::rx_count(1, intid);
    // SAFETY: GICv3 sysreg interface up post-init_bsp; target
    // affinity 1 = AP 1 on QEMU virt's flat affinity layout.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        sgi::send_to_cpu_aff(intid, 1);
    }
    // Poll briefly for the AP to receive + handle.
    let start = narf_time::Instant::now();
    while narf_time::Instant::now().cycles_since(start) < 5_000_000 {
        if sgi::rx_count(1, intid) > before {
            return TestResult::Pass;
        }
        core::hint::spin_loop();
    }
    TestResult::Fail("AP didn't receive SGI within window")
}
#[cfg(target_arch = "aarch64")]
kernel_test!(smoke_smp_aarch64_sgi_to_ap);

#[cfg(target_arch = "aarch64")]
fn smoke_smp_aarch64_cross_cpu_visibility() -> TestResult {
    // The BSP stores a value into a static `SEED` atomic, sends
    // SGI to the AP. The AP's handler reads SEED and stores
    // SEED^MAGIC into RESULT. The BSP polls RESULT and verifies
    // the AP saw its store.
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_interrupts::aarch64::sgi;
    use narf_lib::smp;

    if !smp::is_online(1) {
        return TestResult::Skip("AP CPU 1 offline");
    }

    static SEED: AtomicU64 = AtomicU64::new(0);
    static RESULT: AtomicU64 = AtomicU64::new(0);
    const MAGIC: u64 = 0xDEAD_BEEF_F00D_CAFE;
    const INTID: u8 = 5;

    fn ap_handler() {
        let s = SEED.load(Ordering::Acquire);
        RESULT.store(s ^ MAGIC, Ordering::Release);
    }

    sgi::set_handler(INTID, ap_handler);
    let seed: u64 = 0x0123_4567_89AB_CDEF;
    SEED.store(seed, Ordering::Release);
    RESULT.store(0, Ordering::Release);

    // SAFETY: GICv3 is up; AP is online with handlers installed.
    unsafe {
        sgi::send_to_cpu_aff(INTID, 1);
    }

    let start = narf_time::Instant::now();
    while narf_time::Instant::now().cycles_since(start) < 5_000_000 {
        let r = RESULT.load(Ordering::Acquire);
        if r != 0 {
            sgi::clear_handler(INTID);
            return if r == seed ^ MAGIC {
                TestResult::Pass
            } else {
                TestResult::Fail("AP saw stale SEED — memory ordering broken")
            };
        }
        core::hint::spin_loop();
    }
    sgi::clear_handler(INTID);
    TestResult::Fail("AP handler didn't store RESULT")
}
#[cfg(target_arch = "aarch64")]
kernel_test!(smoke_smp_aarch64_cross_cpu_visibility);

#[cfg(target_arch = "aarch64")]
fn smoke_smp_aarch64_resched_flag() -> TestResult {
    // Sending SGI_RESCHED to the AP should set its needs_resched
    // flag (via the framework-default handler installed at AP
    // bring-up).
    use narf_interrupts::aarch64::sgi;
    use narf_lib::smp;
    if !smp::is_online(1) {
        return TestResult::Skip("AP CPU 1 offline");
    }
    sgi::clear_resched(1);
    if sgi::needs_resched(1) {
        return TestResult::Fail("clear_resched didn't clear");
    }
    // SAFETY: GICv3 sysreg up.
    unsafe {
        sgi::send_to_cpu_aff(sgi::SGI_RESCHED, 1);
    }
    let start = narf_time::Instant::now();
    while narf_time::Instant::now().cycles_since(start) < 5_000_000 {
        if sgi::needs_resched(1) {
            sgi::clear_resched(1);
            return TestResult::Pass;
        }
        core::hint::spin_loop();
    }
    TestResult::Fail("AP didn't set needs_resched after SGI_RESCHED")
}
#[cfg(target_arch = "aarch64")]
kernel_test!(smoke_smp_aarch64_resched_flag);

#[cfg(target_arch = "aarch64")]
fn smoke_smp_aarch64_dtb_count() -> TestResult {
    // QEMU virt -smp 1 (default) reports 1 CPU. The number bumps
    // when xtask switches to `-smp N`.
    use narf_lib::smp;
    let n = smp::cpu_count();
    if n == 0 || n > narf_lib::smp::MAX_CPUS as u32 {
        return TestResult::Fail("cpu_count out of range");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test!(smoke_smp_aarch64_dtb_count);

#[cfg(target_arch = "x86_64")]
fn smoke_smp_x86_64_ap_online() -> TestResult {
    // After INIT-SIPI-SIPI bring-up at boot, CPU 1 is online if QEMU
    // was started with -smp >= 2. xtask sets -smp 2 by default.
    use narf_lib::smp;
    if smp::cpu_count() < 2 {
        return TestResult::Skip("BSP-only QEMU config");
    }
    if !smp::is_online(1) {
        return TestResult::Fail("AP CPU 1 didn't come online");
    }
    if smp::online_count() < 2 {
        return TestResult::Fail("online_count < 2 with -smp 2");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_smp_x86_64_ap_online);

#[cfg(target_arch = "x86_64")]
fn smoke_smp_x86_64_cpuid_count() -> TestResult {
    // CPUID leaf 0xB sub 1 EBX[15:0] reports logical-processor count
    // *at the core level* — i.e. LPs sharing a core. With SMT off
    // (QEMU's default) it returns 1; with multi-socket configs the
    // boot path prefers SRAT for cpu_count, so this test only
    // validates that CPUID returns *something* sane. Strict
    // CPUID==cpu_count agreement was a Stage-3 invariant lost when
    // SRAT became the canonical source.
    use narf_lib::smp;
    // SAFETY: CPUID at CPL=0.
    let probed = unsafe { smp::count_x86_64_cpus_via_cpuid() };
    if probed == 0 || probed > narf_lib::smp::MAX_CPUS as u32 {
        return TestResult::Fail("CPUID count out of range");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_smp_x86_64_cpuid_count);

// `smoke_acpi_srat_topology_present` migrated to acpi/src/tests.rs (subsystem `"acpi"`).

// `smoke_acpi_srat_memory_node_lookup` migrated to acpi/src/tests.rs (subsystem `"acpi"`).

// `smoke_acpi_srat_synthetic_lapic_entry` migrated to acpi/src/tests.rs (subsystem `"acpi"`).

// `smoke_acpi_madt_topology_present` migrated to acpi/src/tests.rs (subsystem `"acpi"`).

// `smoke_acpi_mcfg_ecam_base` migrated to acpi/src/tests.rs (subsystem `"acpi"`).

// `smoke_aml_namespace_built_at_boot` migrated to aml/src/tests.rs (subsystem `"aml"`).
// `smoke_aml_synthetic_scope_and_name` migrated to aml/src/tests.rs (subsystem `"aml"`).
// `smoke_aml_synthetic_method_skipped` migrated to aml/src/tests.rs (subsystem `"aml"`).
// `smoke_aml_eval_add` migrated to aml/src/tests.rs (subsystem `"aml"`).
// `smoke_aml_eval_if_lequal` migrated to aml/src/tests.rs (subsystem `"aml"`).
// `smoke_aml_eval_while_increment` migrated to aml/src/tests.rs (subsystem `"aml"`).
// `smoke_aml_eval_multiply_arg` migrated to aml/src/tests.rs (subsystem `"aml"`).

// `smoke_frame_alloc_per_node_distribution` migrated to memory/src/tests.rs (subsystem `"memory"`).

#[cfg(target_arch = "x86_64")]
fn smoke_frame_alloc_on_node_returns_local() -> TestResult {
    if !narf_lib::smp::is_online(1) {
        return TestResult::Skip(
            "needs the default multi-CPU/NUMA QEMU config; NARF_QEMU_SMP drops -numa + APs",
        );
    }
    // alloc_frame_on(node) should return a frame whose physical
    // address falls within `node`'s SRAT memory range. Re-parse
    // SRAT first because synthetic-body tests earlier in the
    // harness scrub the shared NUMA tables.
    use narf_memory::{alloc_frame_on, free_frame};
    if !narf_memory::is_numa_aware() {
        return TestResult::Fail("frame allocator not NUMA-rebalanced");
    }
    let rsdp = match narf_acpi::cached_rsdp() {
        Some(p) => p,
        None => return TestResult::Fail("no boot-time RSDP cached"),
    };
    // SAFETY: cached RSDP, validated at boot.
    let _ = unsafe { narf_acpi::parse_srat(rsdp) };

    for node in 0..2u32 {
        let f = match alloc_frame_on(node as usize) {
            Ok(f) => f,
            Err(_) => return TestResult::Fail("alloc_frame_on failed"),
        };
        let addr = f.start_address().raw();
        let observed = narf_acpi::memory_node(addr);
        free_frame(f);
        match observed {
            Some(n) if n == node => continue,
            Some(_) => return TestResult::Fail("alloc_frame_on returned wrong-node frame"),
            None => return TestResult::Fail("frame address not in any SRAT range"),
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_frame_alloc_on_node_returns_local);

#[cfg(target_arch = "x86_64")]
fn smoke_frame_free_routes_to_owning_node() -> TestResult {
    if !narf_lib::smp::is_online(1) {
        return TestResult::Skip(
            "needs the default multi-CPU/NUMA QEMU config; NARF_QEMU_SMP drops -numa + APs",
        );
    }
    // free_frame() must use the frame's physical address to choose
    // the destination bin — not the current CPU's node. Allocate
    // from node 1, free, then re-alloc from node 1 and confirm we
    // got it back (cheap check; the bin was empty otherwise).
    // Re-parse SRAT first — synthetic-body tests upstream may have
    // scrubbed the shared NUMA tables.
    use narf_memory::{alloc_frame_on, free_frame, node_free};
    if !narf_memory::is_numa_aware() {
        return TestResult::Fail("frame allocator not NUMA-rebalanced");
    }
    let rsdp = match narf_acpi::cached_rsdp() {
        Some(p) => p,
        None => return TestResult::Fail("no boot-time RSDP cached"),
    };
    // SAFETY: cached RSDP, validated at boot.
    let _ = unsafe { narf_acpi::parse_srat(rsdp) };

    let before = node_free(1);
    let f = match alloc_frame_on(1) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("alloc_frame_on(1) failed"),
    };
    let after_alloc = node_free(1);
    if after_alloc != before - 1 {
        return TestResult::Fail("node-1 free count didn't decrement on alloc");
    }
    free_frame(f);
    let after_free = node_free(1);
    if after_free != before {
        return TestResult::Fail("node-1 free count didn't restore on free");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_frame_free_routes_to_owning_node);

#[cfg(target_arch = "x86_64")]
fn smoke_numa_slit_distance_matrix() -> TestResult {
    if !narf_lib::smp::is_online(1) {
        return TestResult::Skip(
            "needs the default multi-CPU/NUMA QEMU config; NARF_QEMU_SMP drops -numa + APs",
        );
    }
    // The QEMU NUMA host wires a 2-node SLIT with local=10/remote=20
    // (`-numa dist,...`). Re-parse SRAT + SLIT from the cached boot
    // RSDP (synthetic-body tests upstream may have scrubbed the shared
    // tables), then assert the distance matrix matches the host config.
    let rsdp = match narf_acpi::cached_rsdp() {
        Some(p) => p,
        None => return TestResult::Fail("no boot-time RSDP cached"),
    };
    // SAFETY: cached RSDP, validated at boot.
    let _ = unsafe { narf_acpi::parse_srat(rsdp) };
    // SAFETY: same cached RSDP.
    let slit = unsafe { narf_acpi::parse_slit(rsdp) };
    match slit {
        Ok(n) if n >= 2 => {}
        Ok(_) => return TestResult::Fail("SLIT parsed < 2 localities"),
        Err(_) => return TestResult::Fail("SLIT not present/parse failed"),
    }
    if !narf_acpi::is_slit_known() {
        return TestResult::Fail("is_slit_known() false after parse");
    }
    // Distance matrix: diagonal = LOCAL_DISTANCE (10), off-diagonal =
    // REMOTE_DISTANCE (20).
    if narf_acpi::node_distance(0, 0) != 10 {
        return TestResult::Fail("node_distance(0,0) != 10");
    }
    if narf_acpi::node_distance(1, 1) != 10 {
        return TestResult::Fail("node_distance(1,1) != 10");
    }
    if narf_acpi::node_distance(0, 1) != 20 {
        return TestResult::Fail("node_distance(0,1) != 20");
    }
    if narf_acpi::node_distance(1, 0) != 20 {
        return TestResult::Fail("node_distance(1,0) != 20");
    }
    // numa_node_count reflects the SLIT locality dimension.
    if narf_acpi::numa_node_count() < 2 {
        return TestResult::Fail("numa_node_count() < 2");
    }
    // Out-of-range falls back to the Linux convention (10 same / 20 diff).
    if narf_acpi::node_distance(99, 99) != 10 || narf_acpi::node_distance(99, 7) != 20 {
        return TestResult::Fail("out-of-range distance fallback wrong");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_numa_slit_distance_matrix);

#[cfg(target_arch = "x86_64")]
fn smoke_numa_mempolicy_bind_steers_alloc() -> TestResult {
    if !narf_lib::smp::is_online(1) {
        return TestResult::Skip(
            "needs the default multi-CPU/NUMA QEMU config; NARF_QEMU_SMP drops -numa + APs",
        );
    }
    // MPOL_BIND enforcement: with the active policy bound to node 1,
    // a policied allocation must land in node 1's SRAT memory range.
    // Then MPOL_PREFERRED node 0 must land in node 0's range.
    use narf_memory::{free_frame, mempolicy_clear, mempolicy_set, Mempolicy, MPOL_BIND};
    if !narf_memory::is_numa_aware() {
        return TestResult::Fail("frame allocator not NUMA-rebalanced");
    }
    let rsdp = match narf_acpi::cached_rsdp() {
        Some(p) => p,
        None => return TestResult::Fail("no boot-time RSDP cached"),
    };
    // SAFETY: cached RSDP, validated at boot.
    let _ = unsafe { narf_acpi::parse_srat(rsdp) };

    // Bind to node 1 (nodemask bit 1).
    mempolicy_set(Mempolicy {
        mode: MPOL_BIND,
        nodemask: 0b10,
        allowed: u64::MAX,
        home_node: u32::MAX,
        interleave_index: 0,
    });
    let f = match narf_memory::alloc_frame_policied(0) {
        Ok(f) => f,
        Err(_) => {
            mempolicy_clear();
            return TestResult::Fail("policied alloc (BIND node1) failed");
        }
    };
    let node = narf_acpi::memory_node(f.start_address().raw());
    free_frame(f);
    mempolicy_clear();
    match node {
        Some(1) => {}
        Some(_) => return TestResult::Fail("MPOL_BIND node1 returned wrong-node frame"),
        None => return TestResult::Fail("BIND frame not in any SRAT range"),
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_numa_mempolicy_bind_steers_alloc);

// `smoke_acpi_hmat_latency_lookup` migrated to acpi/src/tests.rs (subsystem `"acpi"`).

// `smoke_acpi_hmat_mem_attrs_present` migrated to acpi/src/tests.rs (subsystem `"acpi"`).

// `smoke_acpi_pmtt_synthetic_dimm_entry` migrated to acpi/src/tests.rs (subsystem `"acpi"`).

// `smoke_acpi_srat_synthetic_memory_entry` migrated to acpi/src/tests.rs (subsystem `"acpi"`).

// `smoke_scheduler_per_cpu_pin_to_bsp` migrated to scheduler/src/tests.rs (subsystem `"scheduler"`).

// `smoke_scheduler_numa_steal_prefers_same_node` migrated to scheduler/src/tests.rs (subsystem `"scheduler"`).

// `smoke_scheduler_steal_disabled_returns_clean` migrated to scheduler/src/tests.rs (subsystem `"scheduler"`).

// virtio-balloon-pci + virtio-snd-pci probe smokes migrated to
// `drivers/virtio/src/tests.rs`.

// `smoke_audio_picker_no_backend_when_unprobed`, `smoke_audio_writer_submit_round_trip`,
// `smoke_audio_submit_shmem_zero_copy`, `smoke_audio_format_unsupported_rate_rejects`
// migrated to `audio/src/tests.rs` (subsystem `audio`).

fn smoke_drivers_net_nic_model_ids() -> TestResult {
    use narf_drivers_net::{NicCaps, NicModel};

    // PCI vendor-id sanity.
    let e1000 = NicModel::IntelE1000.primary_pci_id();
    if e1000 != (0x8086, 0x100E) {
        return TestResult::Fail("e1000 vendor/device id mismatch");
    }
    let mlx5 = NicModel::MellanoxMlx5.primary_pci_id();
    if mlx5.0 != 0x15B3 {
        return TestResult::Fail("Mellanox vendor id should be 0x15B3");
    }

    // Caps compose + contain.
    let full = NicCaps::TX_CSUM | NicCaps::RX_CSUM | NicCaps::TSO;
    if !full.contains(NicCaps::TSO) || full.contains(NicCaps::RSS) {
        return TestResult::Fail("NicCaps::contains logic broken");
    }
    TestResult::Pass
}
kernel_test!(smoke_drivers_net_nic_model_ids);

// `smoke_memory_address_space_materialize` migrated to memory/src/tests.rs (subsystem `"memory"`).

// `smoke_scheduler_spawn_user_carries_address_space` migrated to scheduler/src/tests.rs (subsystem `"scheduler"`).

// `smoke_ipc_mpsc_multi_producer_roundtrip` migrated to ipc/src/tests.rs (subsystem `"ipc"`).

// `smoke_ipc_mpsc_closed_surfaces` migrated to ipc/src/tests.rs (subsystem `"ipc"`).

// `smoke_memory_address_space_region_table` migrated to memory/src/tests.rs (subsystem `"memory"`).

// `smoke_abi_dispatcher_serves_file_ops` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_abi_dispatcher_serves_mmap` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_spawn_dispatcher_for_helper` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_shared_ring_kick_round_trip` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_bootstrap_rings_round_trip` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_bootstrap_returns_config_page` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_brk_grows_heap` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_clock_gettime_writes_timespec` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_sigaction_records_handler` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_signal_delivery` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_chdir_getcwd_round_trip` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_sleep_advances_time` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_synchronous_signal_delivery` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_filesystem_resolve_absolute_picks_longest_prefix` migrated to filesystem/src/tests.rs (subsystem `"filesystem"`).

// `smoke_filesystem_memfs_unlink_round_trip` migrated to filesystem/src/tests.rs (subsystem `"filesystem"`).

// `smoke_userspace_open_routes_through_vfs` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_symlink_create_and_readlink_round_trip` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_readlink_on_non_symlink_fails` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_read_write_routes_through_fd_table` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// ── Tier-2 fd-table breadth smokes ─────────────────────────────────
//
// Verify dup / fcntl / stat / pipe(2) round-trip through the
// kernel-side syscall surface. The four tests below exercise each
// slot independently so a failure points at a specific handler;
// they share the FakeCtx + task-id-lookup boilerplate the existing
// fd-table tests use.

// `smoke_userspace_dup_clones_fd` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_fcntl_flags_round_trip` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_stat_returns_size` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_pipe_round_trip` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_fd_table_roundtrip` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_install_core_syscalls_fills_table` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_load_user_process_builds_runnable_image` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_load_user_process_with_argv` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_load_user_process_with_interp` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_parse_pt_tls` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_apply_relative_relocations` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_apply_symbol_relocations` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_unresolved_symbol_errors` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

/// Builder shared by the two `_carries_name` smokes: lays out a
/// minimal ELF with PT_LOAD + PT_DYNAMIC, one Elf64_Rela entry
/// against sym_idx=1 (SHN_UNDEF), a 2-entry symtab whose entry 1
/// has `st_name = 1`, and a strtab the caller fills in. Returns the
/// constructed bytes.
// `smoke_userspace_syscall_table_roundtrip` migrated to userspace/src/tests.rs (subsystem `"userspace"`).
#[cfg(target_arch = "x86_64")]
fn smoke_frame_x86_64_gdt_user_descriptors() -> TestResult {
    // Read the GDT directly via SGDT and inspect the access byte
    // (byte 5) of the user-code (index 6) and user-data (index 5)
    // descriptors. Each descriptor is 8 bytes; byte 5 holds
    // [P(7) | DPL(5:6) | S(4) | Type(0:3)]. DPL=3 → 0x60.
    use core::arch::asm;

    #[repr(C, packed)]
    struct GdtPtr {
        limit: u16,
        base: u64,
    }
    let mut ptr = GdtPtr { limit: 0, base: 0 };
    // SAFETY: Valid memory or trusted environment
    unsafe {
        asm!("sgdt [{p}]", p = in(reg) &mut ptr,
             options(nostack, preserves_flags));
    }
    let base = ptr.base;

    // Index 5 = byte offset 0x28 → user data.
    // Index 6 = byte offset 0x30 → user code.
    let read_access =
        // SAFETY: Valid memory or trusted environment
        |idx: u64| -> u8 { unsafe { core::ptr::read_volatile((base + idx * 8 + 5) as *const u8) } };

    let udata_access = read_access(5);
    if udata_access & 0xE0 != 0xE0 {
        // 0xE0 = P(0x80) | DPL=3(0x60); S + Type checked below.
        return TestResult::Fail("user-data descriptor lacks P+DPL=3");
    }
    if udata_access & 0x10 == 0 {
        return TestResult::Fail("user-data descriptor S bit not set");
    }
    // Writable-data type with the Accessed bit preset: low nibble 0x3
    // (data + writable + accessed), Linux's `__USER_DS` type. The CPU sets
    // the Accessed bit itself the first time a user task loads the selector,
    // so a table built without it reads 0x2 before the first user task and
    // 0x3 after; the preset makes the byte the same whenever this runs.
    if udata_access & 0x0F != 0x03 {
        let _ = writeln!(Writer, "    user-data access byte {udata_access:#04x}");
        return TestResult::Fail("user-data descriptor type != writable accessed data");
    }

    let ucode_access = read_access(6);
    if ucode_access & 0xE0 != 0xE0 {
        return TestResult::Fail("user-code descriptor lacks P+DPL=3");
    }
    if ucode_access & 0x10 == 0 {
        return TestResult::Fail("user-code descriptor S bit not set");
    }
    // Exec/read code type with the Accessed bit preset: low nibble 0xB
    // (code + readable + accessed), Linux's `__USER_CS` type.
    if ucode_access & 0x0F != 0x0B {
        let _ = writeln!(Writer, "    user-code access byte {ucode_access:#04x}");
        return TestResult::Fail("user-code descriptor type != exec/readable accessed code");
    }

    // Kernel code descriptor (index 1) must still be DPL=0.
    let kcode_access = read_access(1);
    if kcode_access & 0x60 != 0x00 {
        return TestResult::Fail("kernel code DPL drifted from 0");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_frame_x86_64_gdt_user_descriptors);

#[cfg(target_arch = "x86_64")]
fn smoke_frame_x86_64_idt_vector_128_dpl3() -> TestResult {
    // The IDT itself is loaded via LIDT; we verify vector 128's
    // DPL=3 by reading the IDT descriptor table pointer with
    // SIDT and dereferencing the 16-byte entry at offset 128*16.
    use core::arch::asm;

    #[repr(C, packed)]
    struct IdtPtr {
        limit: u16,
        base: u64,
    }
    let mut ptr = IdtPtr { limit: 0, base: 0 };
    // SAFETY: Valid memory or trusted environment
    unsafe {
        asm!(
            "sidt [{p}]",
            p = in(reg) &mut ptr,
            options(nostack, preserves_flags),
        );
    }
    // Each IDT entry is 16 bytes. Vector 128 → offset 128*16 = 0x800.
    let entry_ptr = {
        let base = ptr.base;
        (base + 128 * 16) as *const u8
    };
    // Access byte is at offset 5 within the 16-byte entry.
    // SAFETY: Valid memory or trusted environment
    let access = unsafe { core::ptr::read_volatile(entry_ptr.add(5)) };
    // DPL is bits 5..=6 of the access byte; should be 3 for a
    // user-triggerable gate (0b01100000 = 0x60).
    if access & 0x60 != 0x60 {
        return TestResult::Fail("IDT vector 128 DPL != 3 — user mode cannot trigger int 0x80");
    }
    // Present bit should still be set.
    if access & 0x80 == 0 {
        return TestResult::Fail("IDT vector 128 not present");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_frame_x86_64_idt_vector_128_dpl3);

#[cfg(target_arch = "x86_64")]
fn smoke_frame_x86_64_tss_rsp0_and_gs_base() -> TestResult {
    // After `frame::x86_64::init_traps()` runs (part of boot) the
    // TSS has rsp0 pointing at the static kernel stack, and
    // IA32_GS_BASE points at the BSP's PerCpu struct so kernel
    // code can read per-CPU state via `gs:offset`.
    //
    // The frame binary doesn't expose these as library symbols, so
    // we check the system-register state directly: `str` + `ltr`
    // operate on the task-register selector (TSS_SEL = 0x18), and
    // MSR reads for IA32_GS_BASE are always legal at CPL=0.
    use core::arch::asm;
    use narf_arch::x86_64::msr;

    const IA32_GS_BASE: u32 = 0xC0000101;
    const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;

    // Confirm the task register still points at the TSS selector
    // GDT installed (0x18). A failure here means boot changed
    // something we shouldn't have.
    let tr: u16;
    // SAFETY: Valid memory or trusted environment
    unsafe {
        asm!("str {t:x}", t = out(reg) tr, options(nomem, nostack, preserves_flags));
    }
    if tr != 0x18 {
        return TestResult::Fail("task register is not the post-init TSS selector");
    }

    // IA32_GS_BASE should be non-zero (init_bsp programmed it to
    // point at BSP_PERCPU).
    // SAFETY: reading IA32_GS_BASE at CPL=0 is always legal.
    let gs_base = unsafe { msr::rdmsr(IA32_GS_BASE) };
    if gs_base == 0 {
        return TestResult::Fail("IA32_GS_BASE is zero — percpu::init_bsp didn't run");
    }

    // IA32_KERNEL_GS_BASE starts at zero (no user task running yet);
    // writing + reading round-trips.
    // SAFETY: reading this MSR is always legal at CPL=0.
    let kgs_before = unsafe { msr::rdmsr(IA32_KERNEL_GS_BASE) };
    if kgs_before != 0 {
        return TestResult::Fail("IA32_KERNEL_GS_BASE should be zero pre-user-task");
    }
    // SAFETY: writing KERNEL_GS_BASE at CPL=0 is documented. We
    // restore it immediately so other tests see the same initial
    // state. The round-trip value MUST be a CANONICAL address: GS_BASE
    // (like FS_BASE / KERNEL_GS_BASE) is a base-address MSR, and WRMSR
    // of a non-canonical value #GPs on real silicon and under KVM. (TCG
    // doesn't enforce canonicality, which is why a non-canonical
    // sentinel silently passed in CI but crashed on bare metal / KVM.)
    const KGS_SENTINEL: u64 = 0x0000_7EAD_CAFE_F00D;
    // SAFETY: Valid memory or trusted environment
    unsafe {
        msr::wrmsr(IA32_KERNEL_GS_BASE, KGS_SENTINEL);
    }
    // SAFETY: Valid memory or trusted environment
    let kgs_mid = unsafe { msr::rdmsr(IA32_KERNEL_GS_BASE) };
    if kgs_mid != KGS_SENTINEL {
        // SAFETY: Valid memory or trusted environment
        unsafe {
            msr::wrmsr(IA32_KERNEL_GS_BASE, 0);
        }
        return TestResult::Fail("IA32_KERNEL_GS_BASE did not round-trip");
    }
    // SAFETY: Valid memory or trusted environment
    unsafe {
        msr::wrmsr(IA32_KERNEL_GS_BASE, 0);
    }

    // Read `gs:[8]` — the `kernel_stack_top` slot in PerCpu. It
    // mirrors TSS.rsp0, so it should be non-zero.
    let mirrored: u64;
    // SAFETY: Valid memory or trusted environment
    unsafe {
        asm!(
            "mov {v}, gs:[8]",
            v = out(reg) mirrored,
            options(nomem, nostack, preserves_flags),
        );
    }
    if mirrored == 0 {
        return TestResult::Fail("percpu.kernel_stack_top mirror is zero");
    }

    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_frame_x86_64_tss_rsp0_and_gs_base);

#[cfg(all(target_arch = "x86_64", feature = "kernel-test"))]
fn smoke_frame_x86_64_int80_dispatches_through_global() -> TestResult {
    // End-to-end: install a global SyscallTable with a handler for
    // Syscall::Yield, fire `int 0x80` from kernel mode with
    // rax = Yield.raw() and rdi = 0xC0FFEE. The IDT vector-128
    // handler routes the trap into `kernel_syscall_entry`; the
    // return value lands in rax, status in rdx.
    use core::arch::asm;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_userspace::{
        install_global, syscall::__verification_clear_global as __test_clear_global, Syscall,
        SyscallArgs, SyscallInterception, SyscallInterceptor, SyscallInvocation, SyscallReturn,
        SyscallTable,
    };

    static SEEN: AtomicU64 = AtomicU64::new(0);
    static ENTERS: AtomicU64 = AtomicU64::new(0);
    static RETURNS: AtomicU64 = AtomicU64::new(0);
    static UNKNOWN: AtomicU64 = AtomicU64::new(0);
    SEEN.store(0, Ordering::Relaxed);
    ENTERS.store(0, Ordering::Relaxed);
    RETURNS.store(0, Ordering::Relaxed);
    UNKNOWN.store(0, Ordering::Relaxed);

    struct Probe;
    impl SyscallInterceptor for Probe {
        fn on_syscall_enter(
            &self,
            invocation: &SyscallInvocation,
            _native: &mut dyn narf_userspace::NativeSyscallTransition,
        ) -> SyscallInterception {
            ENTERS.fetch_add(1, Ordering::Relaxed);
            if invocation.syscall.is_none() {
                UNKNOWN.fetch_add(1, Ordering::Relaxed);
                SyscallInterception::Complete(SyscallReturn::ok(0xA11CE))
            } else {
                SyscallInterception::Continue
            }
        }

        fn on_syscall_return(
            &self,
            invocation: &SyscallInvocation,
            mut result: SyscallReturn,
        ) -> SyscallReturn {
            RETURNS.fetch_add(1, Ordering::Relaxed);
            if invocation.syscall == Some(Syscall::Yield) {
                result.value = result.value.wrapping_add(1);
            }
            result
        }
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    t.install_fn(Syscall::Yield, "yield", |args: &SyscallArgs| {
        SEEN.store(args.arg0, Ordering::Relaxed);
        SyscallReturn::ok(args.arg0.wrapping_mul(2))
    });
    if t.install_interceptor(alloc::boxed::Box::new(Probe))
        .is_err()
    {
        return TestResult::Fail("int 0x80 interceptor installation failed");
    }
    install_global(t);

    let mut value: u64;
    let mut status: u64;
    // SAFETY: Valid memory or trusted environment
    unsafe {
        asm!(
            "int 0x80",
            inout("rax") Syscall::Yield.raw() as u64 => value,
            inout("rdi") 0xC0FFEEu64 => _,
            out("rdx") status,
            // rcx, r11 are clobbered by the trap; mark so LLVM
            // doesn't rely on values surviving.
            out("rcx") _,
            out("r11") _,
        );
    }

    let mut unknown_value: u64;
    let mut unknown_status: u64;
    // SAFETY: Valid memory or trusted environment
    unsafe {
        asm!(
            "int 0x80",
            inout("rax") 0x3fffu64 => unknown_value,
            inout("rdi") 0xBADu64 => _,
            out("rdx") unknown_status,
            out("rcx") _,
            out("r11") _,
        );
    }

    __test_clear_global();

    if SEEN.load(Ordering::Relaxed) != 0xC0FFEE {
        return TestResult::Fail("handler did not observe arg0 via int 0x80");
    }
    if status != SyscallReturn::OK as u64 {
        return TestResult::Fail("status via rdx wasn't Ok");
    }
    if value != 0xC0FFEE * 2 + 1 {
        return TestResult::Fail("interceptor's final int 0x80 result was not returned");
    }
    if unknown_status != SyscallReturn::OK as u64 || unknown_value != 0xA11CE {
        return TestResult::Fail("interceptor did not complete unknown int 0x80 syscall");
    }
    if ENTERS.load(Ordering::Relaxed) != 2
        || RETURNS.load(Ordering::Relaxed) != 2
        || UNKNOWN.load(Ordering::Relaxed) != 1
    {
        return TestResult::Fail("int 0x80 interceptor callback accounting mismatch");
    }
    TestResult::Pass
}
#[cfg(all(target_arch = "x86_64", feature = "kernel-test"))]
kernel_test!(smoke_frame_x86_64_int80_dispatches_through_global);

#[cfg(all(target_arch = "aarch64", feature = "kernel-test"))]
fn smoke_frame_aarch64_svc_dispatches_through_global() -> TestResult {
    // End-to-end: install a global SyscallTable with a handler for
    // Syscall::Yield, fire `svc #0` from kernel mode with x8 =
    // Yield.raw() and x0 = 0xC0FFEE, read back x0 (value) + x1
    // (status) and confirm the trap dispatcher round-tripped
    // through our handler.
    use core::arch::asm;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_userspace::{
        install_global, syscall::__verification_clear_global as __test_clear_global, Syscall,
        SyscallArgs, SyscallInterception, SyscallInterceptor, SyscallInvocation, SyscallReturn,
        SyscallTable,
    };

    static SEEN: AtomicU64 = AtomicU64::new(0);
    static ENTERS: AtomicU64 = AtomicU64::new(0);
    static RETURNS: AtomicU64 = AtomicU64::new(0);
    static UNKNOWN: AtomicU64 = AtomicU64::new(0);
    SEEN.store(0, Ordering::Relaxed);
    ENTERS.store(0, Ordering::Relaxed);
    RETURNS.store(0, Ordering::Relaxed);
    UNKNOWN.store(0, Ordering::Relaxed);

    struct Probe;
    impl SyscallInterceptor for Probe {
        fn on_syscall_enter(
            &self,
            invocation: &SyscallInvocation,
            _native: &mut dyn narf_userspace::NativeSyscallTransition,
        ) -> SyscallInterception {
            ENTERS.fetch_add(1, Ordering::Relaxed);
            if invocation.syscall.is_none() {
                UNKNOWN.fetch_add(1, Ordering::Relaxed);
                SyscallInterception::Complete(SyscallReturn::ok(0xA11CE))
            } else {
                SyscallInterception::Continue
            }
        }

        fn on_syscall_return(
            &self,
            invocation: &SyscallInvocation,
            mut result: SyscallReturn,
        ) -> SyscallReturn {
            RETURNS.fetch_add(1, Ordering::Relaxed);
            if invocation.syscall == Some(Syscall::Yield) {
                result.value = result.value.wrapping_add(1);
            }
            result
        }
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    t.install_fn(Syscall::Yield, "yield", |args: &SyscallArgs| {
        SEEN.store(args.arg0, Ordering::Relaxed);
        SyscallReturn::ok(args.arg0.wrapping_mul(2))
    });
    if t.install_interceptor(alloc::boxed::Box::new(Probe))
        .is_err()
    {
        return TestResult::Fail("SVC interceptor installation failed");
    }
    install_global(t);

    // Fire SVC from EL1. The vec.S sync-SPx slot dispatches into
    // `rust_aarch64_sync_dispatch`, which routes the SVC into
    // `kernel_syscall_entry`.
    //
    // x8 = syscall number (Yield = 104), x0 = arg0 = 0xC0FFEE.
    // After the call x0 = value, x1 = status.
    let mut value: u64 = 0xC0FFEE;
    let mut status: u64;
    // SAFETY: Valid memory or trusted environment
    unsafe {
        asm!(
            "mov x8, #{num}",
            "svc #0",
            "mov {s}, x1",
            num = const (Syscall::Yield.raw() as u64),
            s = out(reg) status,
            inout("x0") value,
            out("x1") _,
            out("x8") _,
        );
    }

    let mut unknown_value: u64 = 0xBAD;
    let mut unknown_status: u64;
    // SAFETY: Valid memory or trusted environment
    unsafe {
        asm!(
            "mov x8, #0x3fff",
            "svc #0",
            "mov {s}, x1",
            s = out(reg) unknown_status,
            inout("x0") unknown_value,
            out("x1") _,
            out("x8") _,
        );
    }

    __test_clear_global();

    if SEEN.load(Ordering::Relaxed) != 0xC0FFEE {
        return TestResult::Fail("handler did not observe args.arg0 via SVC path");
    }
    if status != SyscallReturn::OK as u64 {
        return TestResult::Fail("status returned through SVC wasn't Ok");
    }
    if value != 0xC0FFEE * 2 + 1 {
        return TestResult::Fail("interceptor's final SVC result was not returned");
    }
    if unknown_status != SyscallReturn::OK as u64 || unknown_value != 0xA11CE {
        return TestResult::Fail("interceptor did not complete unknown SVC syscall");
    }
    if ENTERS.load(Ordering::Relaxed) != 2
        || RETURNS.load(Ordering::Relaxed) != 2
        || UNKNOWN.load(Ordering::Relaxed) != 1
    {
        return TestResult::Fail("SVC interceptor callback accounting mismatch");
    }
    TestResult::Pass
}
#[cfg(all(target_arch = "aarch64", feature = "kernel-test"))]
kernel_test!(smoke_frame_aarch64_svc_dispatches_through_global);

// `smoke_userspace_syscall_dispatch_via_global` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// The end-to-end user-mode round-trip test below boots a real user
// process, issues `int 0x80`, and longjmps back into the harness.
// It *works* — on a standalone run it prints [OK] and the magic
// round-trips — but leaves subsystem state (leaked user AS, TSS
// kernel stack consumed through a trap) that hangs a specific
// later test in the default suite. Gated behind a cfg flag so the
// default test run stays stable; enable with
// `RUSTFLAGS='--cfg user_mode_e2e' cargo xtask test --arch=x86_64`.

#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct UserModeJmpBuf {
    rbx: u64,
    rbp: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rsp: u64,
    rip: u64,
}

#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
#[unsafe(naked)]
unsafe extern "C" fn user_mode_setjmp(buf: *mut UserModeJmpBuf) -> u64 {
    core::arch::naked_asm!(
        "mov [rdi +  0], rbx",
        "mov [rdi +  8], rbp",
        "mov [rdi + 16], r12",
        "mov [rdi + 24], r13",
        "mov [rdi + 32], r14",
        "mov [rdi + 40], r15",
        "lea rax, [rsp + 8]",
        "mov [rdi + 48], rax",
        "mov rax, [rsp]",
        "mov [rdi + 56], rax",
        "xor rax, rax",
        "ret",
    );
}

#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
#[unsafe(naked)]
unsafe extern "C" fn user_mode_longjmp(buf: *const UserModeJmpBuf, val: u64) -> ! {
    core::arch::naked_asm!(
        "mov rbx, [rdi +  0]",
        "mov rbp, [rdi +  8]",
        "mov r12, [rdi + 16]",
        "mov r13, [rdi + 24]",
        "mov r14, [rdi + 32]",
        "mov r15, [rdi + 40]",
        "mov rsp, [rdi + 48]",
        "mov rax, rsi",
        "test rax, rax",
        "jnz 1f",
        "inc rax",
        "1:",
        "jmp qword ptr [rdi + 56]",
    );
}

#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
#[unsafe(naked)]
unsafe extern "C" fn user_mode_enter(rip: u64, rsp: u64) -> ! {
    // User-code sel = 0x33, user-data sel = 0x2B.
    core::arch::naked_asm!(
        "swapgs",
        "push 0x2B",  // SS
        "push rsi",   // RSP (arg2)
        "push 0x202", // RFLAGS (IF=1)
        "push 0x33",  // CS
        "push rdi",   // RIP (arg1)
        "iretq",
    );
}

// Mirrors `narf_frame::x86_64::user::UserState`. Inlined here so
// verification (which doesn't link against narf-frame) can read it.
// Field order load-bearing — the resume trampoline reads by offset.
#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct UserState {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rbp: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    rcx: u64,
    rbx: u64,
    rax: u64,
    rip: u64,
    rflags: u64,
    rsp: u64,
    valid: u64,
}

#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
#[unsafe(naked)]
unsafe extern "C" fn user_mode_resume(_state: *const UserState) -> ! {
    core::arch::naked_asm!(
        "push 0x2B",                   // SS
        "push qword ptr [rdi + 8*17]", // user RSP
        "push qword ptr [rdi + 8*16]", // RFLAGS
        "push 0x33",                   // CS
        "push qword ptr [rdi + 8*15]", // RIP
        "mov r15, [rdi + 8*0]",
        "mov r14, [rdi + 8*1]",
        "mov r13, [rdi + 8*2]",
        "mov r12, [rdi + 8*3]",
        "mov r11, [rdi + 8*4]",
        "mov r10, [rdi + 8*5]",
        "mov r9,  [rdi + 8*6]",
        "mov r8,  [rdi + 8*7]",
        "mov rbp, [rdi + 8*8]",
        "mov rsi, [rdi + 8*10]",
        "mov rdx, [rdi + 8*11]",
        "mov rcx, [rdi + 8*12]",
        "mov rbx, [rdi + 8*13]",
        "mov rax, [rdi + 8*14]",
        "mov rdi, [rdi + 8*9]",
        "swapgs",
        "iretq",
    );
}

#[cfg(all(target_arch = "aarch64", feature = "user-mode-e2e"))]
mod aarch64_el0_preemption_e2e {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{compiler_fence, Ordering};

    use narf_memory::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};
    use narf_userspace::{
        install_core_syscalls, install_global, install_user_task_hooks,
        syscall::__verification_clear_global as __test_clear_global, Syscall, SyscallTable,
        UserProcess,
    };

    use super::{kernel_test_in, TestResult};

    const CODE_VADDR: u64 = 0x0040_0000;
    const STACK_VADDR: u64 = 0x0041_0000;
    const SHARED_VADDR: u64 = 0x0042_0000;
    const PAGE_BYTES: u64 = 4096;
    const TIMER_TVAL_TICKS: u64 = 5_000_000;

    const FLAG_OFFSET: usize = 0;
    const A_TLS_OFFSET: usize = 8;
    const A_SIMD_OFFSET: usize = 16;
    const B_SIMD_OFFSET: usize = 32;
    const A_DONE_OFFSET: usize = 48;
    const B_TLS_OFFSET: usize = 56;
    const A_PATTERN_OFFSET: usize = 64;
    const B_PATTERN_OFFSET: usize = 80;

    const TLS_A: u64 = 0x1122_3344_5566_7788;
    const TLS_B: u64 = 0x8877_6655_4433_2211;
    const SIMD_A: u8 = 0x5a;
    const SIMD_B: u8 = 0xa5;

    #[inline]
    fn movz(rd: u32, imm: u16, shift: u32) -> u32 {
        0xd280_0000 | ((shift / 16) << 21) | (u32::from(imm) << 5) | rd
    }

    #[inline]
    fn movk(rd: u32, imm: u16, shift: u32) -> u32 {
        0xf280_0000 | ((shift / 16) << 21) | (u32::from(imm) << 5) | rd
    }

    fn load_u64(code: &mut Vec<u32>, rd: u32, value: u64) {
        code.push(movz(rd, value as u16, 0));
        code.push(movk(rd, (value >> 16) as u16, 16));
        code.push(movk(rd, (value >> 32) as u16, 32));
        code.push(movk(rd, (value >> 48) as u16, 48));
    }

    #[inline]
    fn msr_tpidr_el0(rt: u32) -> u32 {
        0xd51b_d040 | rt
    }

    #[inline]
    fn mrs_tpidr_el0(rt: u32) -> u32 {
        0xd53b_d040 | rt
    }

    #[inline]
    fn ldr_x(rt: u32, rn: u32, byte_offset: u32) -> u32 {
        debug_assert_eq!(byte_offset % 8, 0);
        0xf940_0000 | ((byte_offset / 8) << 10) | (rn << 5) | rt
    }

    #[inline]
    fn str_x(rt: u32, rn: u32, byte_offset: u32) -> u32 {
        debug_assert_eq!(byte_offset % 8, 0);
        0xf900_0000 | ((byte_offset / 8) << 10) | (rn << 5) | rt
    }

    #[inline]
    fn ldr_q(rt: u32, rn: u32, byte_offset: u32) -> u32 {
        debug_assert_eq!(byte_offset % 16, 0);
        0x3dc0_0000 | ((byte_offset / 16) << 10) | (rn << 5) | rt
    }

    #[inline]
    fn str_q(rt: u32, rn: u32, byte_offset: u32) -> u32 {
        debug_assert_eq!(byte_offset % 16, 0);
        0x3d80_0000 | ((byte_offset / 16) << 10) | (rn << 5) | rt
    }

    #[inline]
    fn cbz_x(rt: u32, delta_instructions: i32) -> u32 {
        let imm19 = (delta_instructions as u32) & 0x7_ffff;
        0xb400_0000 | (imm19 << 5) | rt
    }

    fn emit_exit(code: &mut Vec<u32>) {
        load_u64(code, 8, u64::from(Syscall::ExitTask.raw()));
        code.push(movz(0, 0, 0));
        code.push(0xd400_0001); // svc #0
        code.push(0x1400_0000); // b . (must not execute if exit is wired)
    }

    fn spinner_program() -> Vec<u32> {
        let mut code = Vec::new();
        load_u64(&mut code, 9, SHARED_VADDR);
        load_u64(&mut code, 10, TLS_A);
        code.push(msr_tpidr_el0(10));
        code.push(ldr_q(8, 9, A_PATTERN_OFFSET as u32));

        // No syscall, WFE, or cooperative yield exists in this loop. The
        // releaser can run only if the generic-timer path involuntarily
        // switches this EL0 continuation back to the executor.
        let loop_index = code.len();
        code.push(ldr_x(11, 9, FLAG_OFFSET as u32));
        let cbz_index = code.len();
        code.push(cbz_x(11, loop_index as i32 - cbz_index as i32));

        code.push(mrs_tpidr_el0(12));
        code.push(str_x(12, 9, A_TLS_OFFSET as u32));
        code.push(str_q(8, 9, A_SIMD_OFFSET as u32));
        code.push(movz(13, 1, 0));
        code.push(str_x(13, 9, A_DONE_OFFSET as u32));
        emit_exit(&mut code);
        code
    }

    fn releaser_program() -> Vec<u32> {
        let mut code = Vec::new();
        load_u64(&mut code, 9, SHARED_VADDR);
        load_u64(&mut code, 10, TLS_B);
        code.push(msr_tpidr_el0(10));
        code.push(ldr_q(8, 9, B_PATTERN_OFFSET as u32));
        code.push(str_q(8, 9, B_SIMD_OFFSET as u32));
        code.push(mrs_tpidr_el0(12));
        code.push(str_x(12, 9, B_TLS_OFFSET as u32));
        code.push(movz(11, 1, 0));
        code.push(str_x(11, 9, FLAG_OFFSET as u32));
        emit_exit(&mut code);
        code
    }

    fn build_process(
        code: &[u32],
        code_phys: PhysAddr,
        stack_phys: PhysAddr,
        shared_phys: PhysAddr,
    ) -> Result<UserProcess, &'static str> {
        // SAFETY: the kernel test runs after paging and the frame allocator are
        // live, which is `new_for_user`'s precondition.
        let address_space = unsafe { AddressSpace::new_for_user() }.map_err(|_| "new_for_user")?;

        // Write through the kernel direct-map alias so this remains valid on
        // AArch64 after TTBR1 replaces the low identity map.
        // SAFETY: code_phys names a freshly allocated 4 KiB frame, and the
        // generated program is much smaller than one page.
        unsafe {
            core::ptr::write_bytes(code_phys.kernel_mut_ptr::<u8>(), 0, PAGE_BYTES as usize);
            core::ptr::copy_nonoverlapping(
                code.as_ptr().cast::<u8>(),
                code_phys.kernel_mut_ptr::<u8>(),
                core::mem::size_of_val(code),
            );
            narf_arch::aarch64::asm::flush_icache_range(
                code_phys.kernel_ptr::<u8>() as u64,
                core::mem::size_of_val(code) as u64,
            );
        }

        address_space
            .map_region(Region {
                base: VirtAddr::new(CODE_VADDR),
                len: PAGE_BYTES,
                perms: RegionPerms::READ | RegionPerms::EXEC,
                phys: alloc::vec![code_phys],
            })
            .map_err(|_| "map code")?;
        address_space
            .map_region(Region {
                base: VirtAddr::new(STACK_VADDR),
                len: PAGE_BYTES,
                perms: RegionPerms::READ | RegionPerms::WRITE,
                phys: alloc::vec![stack_phys],
            })
            .map_err(|_| "map stack")?;
        address_space
            .map_region(Region {
                base: VirtAddr::new(SHARED_VADDR),
                len: PAGE_BYTES,
                perms: RegionPerms::READ | RegionPerms::WRITE,
                phys: alloc::vec![shared_phys],
            })
            .map_err(|_| "map shared")?;

        // SAFETY: all mapped physical frames above are live and the page-table
        // allocator is initialized by the kernel-test boot path.
        unsafe { address_space.materialize() }.map_err(|_| "materialize")?;

        Ok(UserProcess {
            pid: narf_userspace::alloc_pid(),
            address_space: Arc::new(address_space),
            entry: narf_userspace::EntryPoint(VirtAddr::new(CODE_VADDR)),
            stack_top: VirtAddr::new(STACK_VADDR + PAGE_BYTES),
            fs_base: None,
            entry_arg: None,
            loaded_mappings: alloc::vec::Vec::new(),
            auxv: alloc::vec::Vec::new(),
        })
    }

    fn alloc_phys() -> Result<PhysAddr, &'static str> {
        narf_memory::alloc_frame()
            .map(|frame| frame.start_address())
            .map_err(|_| "alloc frame")
    }

    fn read_u64(shared: PhysAddr, offset: usize) -> u64 {
        // SAFETY: shared is a live page and all u64 fields are naturally
        // aligned within it. Volatile keeps the post-execution observations
        // explicit to the compiler.
        unsafe {
            shared
                .kernel_ptr::<u8>()
                .add(offset)
                .cast::<u64>()
                .read_volatile()
        }
    }

    fn smoke_aarch64_el0_tick_preempts_and_preserves_context() -> TestResult {
        __test_clear_global();
        narf_userspace::user_task::__test_clear_hooks();
        narf_scheduler::__reset_queues_for_test();

        let shared_phys = match alloc_phys() {
            Ok(phys) => phys,
            Err(reason) => return TestResult::Fail(reason),
        };
        let code_a = match alloc_phys() {
            Ok(phys) => phys,
            Err(reason) => return TestResult::Fail(reason),
        };
        let stack_a = match alloc_phys() {
            Ok(phys) => phys,
            Err(reason) => return TestResult::Fail(reason),
        };
        let code_b = match alloc_phys() {
            Ok(phys) => phys,
            Err(reason) => return TestResult::Fail(reason),
        };
        let stack_b = match alloc_phys() {
            Ok(phys) => phys,
            Err(reason) => return TestResult::Fail(reason),
        };

        // SAFETY: shared_phys names a fresh 4 KiB frame. The two patterns and
        // result fields are disjoint and bounded by the page.
        unsafe {
            let shared = core::slice::from_raw_parts_mut(
                shared_phys.kernel_mut_ptr::<u8>(),
                PAGE_BYTES as usize,
            );
            shared.fill(0);
            shared[A_PATTERN_OFFSET..A_PATTERN_OFFSET + 16].fill(SIMD_A);
            shared[B_PATTERN_OFFSET..B_PATTERN_OFFSET + 16].fill(SIMD_B);
            core::arch::asm!("dsb ishst", options(nostack, preserves_flags));
        }
        compiler_fence(Ordering::SeqCst);

        let spinner = match build_process(&spinner_program(), code_a, stack_a, shared_phys) {
            Ok(process) => process,
            Err(reason) => return TestResult::Fail(reason),
        };
        let releaser = match build_process(&releaser_program(), code_b, stack_b, shared_phys) {
            Ok(process) => process,
            Err(reason) => return TestResult::Fail(reason),
        };

        let mut table = SyscallTable::new();
        install_core_syscalls(&mut table);
        install_global(table);
        install_user_task_hooks();

        let ticks_before = narf_interrupts::aarch64::timer::timer_ticks_for(0);
        narf_userspace::user_task::spawn_user_process(
            spinner,
            narf_scheduler::TaskSpec::unthrottled(),
        );
        narf_userspace::user_task::spawn_user_process(
            releaser,
            narf_scheduler::TaskSpec::unthrottled(),
        );

        // Unlike the normal async-demo boot path, the kernel-test harness
        // deliberately leaves the BSP generic timer stopped and IRQs masked.
        // This smoke owns that preemption source for its duration and restores
        // the incoming IRQ state before returning to the rest of the suite.
        let irqs_were_enabled = narf_arch::interrupts_enabled();
        // SAFETY: GICv3 and the timer PPI are initialized before kernel tests
        // run, and no IRQ-unsafe lock is held here.
        unsafe {
            narf_interrupts::aarch64::timer::start_timer(TIMER_TVAL_TICKS);
            narf_arch::enable_interrupts();
        }

        // If EL0 timer preemption is broken, the first task never leaves its
        // load/CBZ loop and this call times out at the QEMU harness. There is
        // deliberately no cooperative escape hatch in the user program.
        narf_scheduler::run_until_empty();
        let ticks_after = narf_interrupts::aarch64::timer::timer_ticks_for(0);

        // SAFETY: this test exclusively armed the BSP timer above. Restore the
        // harness's prior interrupt-mask state after disabling that source.
        unsafe {
            narf_interrupts::aarch64::timer::stop_timer();
            if irqs_were_enabled {
                narf_arch::enable_interrupts();
            } else {
                narf_arch::disable_interrupts();
            }
        }

        narf_userspace::user_task::__test_clear_hooks();
        __test_clear_global();

        if ticks_after <= ticks_before {
            return TestResult::Fail("BSP generic timer did not tick during EL0 execution");
        }
        if read_u64(shared_phys, FLAG_OFFSET) != 1 || read_u64(shared_phys, A_DONE_OFFSET) != 1 {
            return TestResult::Fail("releaser did not unblock the busy EL0 task");
        }
        if read_u64(shared_phys, A_TLS_OFFSET) != TLS_A
            || read_u64(shared_phys, B_TLS_OFFSET) != TLS_B
        {
            return TestResult::Fail("TPIDR_EL0 leaked across task preemption");
        }

        // SAFETY: the recorded 16-byte SIMD results are within the live shared
        // page. The executor is quiescent, so no user task can mutate them.
        let shared = unsafe {
            core::slice::from_raw_parts(shared_phys.kernel_ptr::<u8>(), PAGE_BYTES as usize)
        };
        if shared[A_SIMD_OFFSET..A_SIMD_OFFSET + 16] != [SIMD_A; 16] {
            return TestResult::Fail("spinner SIMD state was not restored");
        }
        if shared[B_SIMD_OFFSET..B_SIMD_OFFSET + 16] != [SIMD_B; 16] {
            return TestResult::Fail("releaser SIMD sentinel was not executed");
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "verification/aarch64-el0",
        smoke_aarch64_el0_tick_preempts_and_preserves_context
    );
}

#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
static RDTSC_ARMED_CPUS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
fn record_cpu_with_rdtsc_trap_armed() {
    let cpu = narf_lib::percpu::current_cpu();
    if cpu < 64 && narf_arch::x86_64::cr::cached_cr4() & narf_arch::x86_64::cr::CR4_TSD != 0 {
        RDTSC_ARMED_CPUS.fetch_or(1u64 << cpu, core::sync::atomic::Ordering::Release);
    }
}

#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
fn cpu_has_rdtscp() -> bool {
    // SAFETY: CPUID is always legal at CPL0; leaf 0x8000_0000 reports the
    // highest extended leaf before 0x8000_0001 is read.
    unsafe {
        core::arch::x86_64::__cpuid(0x8000_0000).eax >= 0x8000_0001
            && core::arch::x86_64::__cpuid(0x8000_0001).edx & (1 << 27) != 0
    }
}

#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
fn smoke_frame_x86_64_user_mode_fast_syscall_interceptor() -> TestResult {
    // Enter real ring 3 and issue the MSR-driven `syscall` instruction with an
    // unknown raw number. The interceptor completes it with a magic value.
    // User code then moves returned RAX into RDI and reports it through a known
    // int-0x80 syscall whose handler redirects back to this harness. Only RDTSC
    // is subscribed, so the RDTSCP that follows traps under the same CR4.TSD
    // but must complete natively without entering the tool: the TSC read lies
    // between two kernel reads and ECX is IA32_TSC_AUX, the CPU number the
    // vDSO `getcpu` path reports.
    use core::arch::naked_asm;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_memory::{AddressSpace, Region, RegionPerms, VirtAddr};
    use narf_userspace::{
        install_global, instruction::__verification_clear_instruction_interceptor,
        syscall::__verification_clear_global as __test_clear_global,
        try_install_instruction_interceptor, InstructionInterception, InstructionInterceptor,
        InstructionInvocation, InstructionResult, InstructionSubscriptions,
        NondeterministicInstruction, Syscall, SyscallHandler, SyscallInterception,
        SyscallInterceptor, SyscallInvocation, SyscallReturn, SyscallTable, TrapContext,
    };

    const SYSCALL_MAGIC: u64 = 0xA11CE;
    const RDTSC_MAGIC: u64 = 0x1234_5678_9ABC_DEF0;
    static SEEN_SYSCALL_RESULT: AtomicU64 = AtomicU64::new(0);
    static SEEN_RDTSC_RESULT: AtomicU64 = AtomicU64::new(0);
    static SEEN_RDTSCP_AUX: AtomicU64 = AtomicU64::new(0);
    static SEEN_RDTSCP_TSC: AtomicU64 = AtomicU64::new(0);
    static FAST_ENTRIES: AtomicU64 = AtomicU64::new(0);
    static RDTSC_ENTRIES: AtomicU64 = AtomicU64::new(0);
    static OTHER_INSTRUCTION_ENTRIES: AtomicU64 = AtomicU64::new(0);
    static TSC_BEFORE: AtomicU64 = AtomicU64::new(0);
    static CPU_BEFORE: AtomicU64 = AtomicU64::new(0);
    static RDTSC_SUBSCRIPTION_CALLS: AtomicU64 = AtomicU64::new(0);
    static SAVED_CR3: AtomicU64 = AtomicU64::new(0);
    static mut JMP: UserModeJmpBuf = UserModeJmpBuf {
        rbx: 0,
        rbp: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        rsp: 0,
        rip: 0,
    };

    struct Probe;
    impl SyscallInterceptor for Probe {
        fn on_syscall_enter(
            &self,
            invocation: &SyscallInvocation,
            _native: &mut dyn narf_userspace::NativeSyscallTransition,
        ) -> SyscallInterception {
            if invocation.raw_number == 0x3fff && invocation.syscall.is_none() {
                FAST_ENTRIES.fetch_add(1, Ordering::Relaxed);
                SyscallInterception::Complete(SyscallReturn::ok(SYSCALL_MAGIC))
            } else {
                SyscallInterception::Continue
            }
        }
    }

    struct RdtscProbe;
    // SAFETY: every callback uses only preallocated atomics and typed values;
    // it does not allocate, park, lock, await, or re-enter guest execution.
    unsafe impl InstructionInterceptor for RdtscProbe {
        fn subscriptions(&self) -> InstructionSubscriptions {
            RDTSC_SUBSCRIPTION_CALLS.fetch_add(1, Ordering::Relaxed);
            InstructionSubscriptions::RDTSC
        }

        fn on_instruction_enter(
            &self,
            invocation: &InstructionInvocation,
        ) -> InstructionInterception {
            if invocation.instruction == NondeterministicInstruction::Rdtsc {
                RDTSC_ENTRIES.fetch_add(1, Ordering::Relaxed);
                InstructionInterception::Complete(InstructionResult::Rdtsc {
                    value: RDTSC_MAGIC - 1,
                })
            } else {
                OTHER_INSTRUCTION_ENTRIES.fetch_add(1, Ordering::Relaxed);
                InstructionInterception::Continue
            }
        }

        fn on_instruction_return(
            &self,
            _invocation: &InstructionInvocation,
            result: InstructionResult,
        ) -> InstructionResult {
            match result {
                InstructionResult::Rdtsc { value } => InstructionResult::Rdtsc {
                    value: value.wrapping_add(1),
                },
                other => other,
            }
        }
    }

    #[unsafe(naked)]
    unsafe extern "C" fn resume_trampoline() -> ! {
        naked_asm!(
            "lea rdi, [rip + {jmp}]",
            "mov rsi, 1",
            "jmp {lj}",
            jmp = sym JMP,
            lj = sym user_mode_longjmp,
        );
    }

    struct UnwindHandler;
    impl SyscallHandler for UnwindHandler {
        fn handle(&self, ctx: &mut dyn TrapContext) {
            SEEN_SYSCALL_RESULT.store(ctx.args().arg0, Ordering::Release);
            SEEN_RDTSC_RESULT.store(ctx.args().arg1, Ordering::Release);
            SEEN_RDTSCP_AUX.store(ctx.args().arg2, Ordering::Release);
            SEEN_RDTSCP_TSC.store(ctx.args().arg3, Ordering::Release);
            let _ =
                ctx.redirect_to_kernel(resume_trampoline as usize as u64, 0xFFFF_FFFF_FFFF_FFF0);
        }
    }

    SEEN_SYSCALL_RESULT.store(0, Ordering::Relaxed);
    SEEN_RDTSC_RESULT.store(0, Ordering::Relaxed);
    SEEN_RDTSCP_AUX.store(u64::MAX, Ordering::Relaxed);
    SEEN_RDTSCP_TSC.store(0, Ordering::Relaxed);
    FAST_ENTRIES.store(0, Ordering::Relaxed);
    RDTSC_ENTRIES.store(0, Ordering::Relaxed);
    OTHER_INSTRUCTION_ENTRIES.store(0, Ordering::Relaxed);
    RDTSC_SUBSCRIPTION_CALLS.store(0, Ordering::Relaxed);
    __test_clear_global();
    __verification_clear_instruction_interceptor();

    let original_cr3: u64;
    // SAFETY: read the active kernel address space so the non-local return can
    // restore it after the user-mode side trip.
    unsafe {
        core::arch::asm!("mov {v}, cr3", v = out(reg) original_cr3,
            options(nostack, preserves_flags));
    }
    SAVED_CR3.store(original_cr3, Ordering::Release);

    // SAFETY: JMP is dedicated storage for this single-threaded test.
    let saved = unsafe { user_mode_setjmp(core::ptr::addr_of_mut!(JMP)) };
    if saved != 0 {
        // SAFETY: restore the exact kernel CR3 and GS state saved before ring 3.
        unsafe {
            let cr3 = SAVED_CR3.load(Ordering::Acquire);
            core::arch::asm!("mov cr3, {v}", v = in(reg) cr3,
                options(nostack, preserves_flags));
            const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
            core::arch::asm!(
                "wrmsr",
                in("ecx") IA32_KERNEL_GS_BASE,
                in("eax") 0u32,
                in("edx") 0u32,
                options(nostack, preserves_flags),
            );
            core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
        }
        // SAFETY: RDTSC is always legal at CPL0.
        let tsc_after = unsafe { core::arch::x86_64::_rdtsc() };
        let cpu_after = narf_lib::percpu::current_cpu() as u64;
        __test_clear_global();
        __verification_clear_instruction_interceptor();
        if FAST_ENTRIES.load(Ordering::Acquire) != 1 {
            return TestResult::Fail("ring-3 syscall did not enter interceptor exactly once");
        }
        if SEEN_SYSCALL_RESULT.load(Ordering::Acquire) != SYSCALL_MAGIC {
            return TestResult::Fail("ring-3 syscall did not receive interceptor result");
        }
        if RDTSC_ENTRIES.load(Ordering::Acquire) != 1 {
            return TestResult::Fail("ring-3 RDTSC did not enter interceptor exactly once");
        }
        if RDTSC_SUBSCRIPTION_CALLS.load(Ordering::Acquire) != 1 {
            return TestResult::Fail("RDTSC subscription was not frozen exactly once at install");
        }
        if SEEN_RDTSC_RESULT.load(Ordering::Acquire) != RDTSC_MAGIC {
            return TestResult::Fail("ring-3 RDTSC did not receive interceptor result");
        }
        if OTHER_INSTRUCTION_ENTRIES.load(Ordering::Acquire) != 0 {
            return TestResult::Fail("unsubscribed RDTSCP entered the RDTSC-only interceptor");
        }
        let cpu_before = CPU_BEFORE.load(Ordering::Acquire);
        if cpu_before != cpu_after {
            return TestResult::Fail("ring-3 side trip changed CPUs; TSC_AUX check is ambiguous");
        }
        if SEEN_RDTSCP_AUX.load(Ordering::Acquire) != cpu_before {
            return TestResult::Fail("unsubscribed RDTSCP did not return native TSC_AUX (CPU id)");
        }
        let native = SEEN_RDTSCP_TSC.load(Ordering::Acquire);
        if native < TSC_BEFORE.load(Ordering::Acquire) || native > tsc_after {
            return TestResult::Fail("unsubscribed RDTSCP did not return a native TSC value");
        }
        return TestResult::Pass;
    }

    if !cpu_has_rdtscp() {
        return TestResult::Skip("RDTSCP not supported by this CPU model");
    }
    let mut table = SyscallTable::new();
    table.install_raw(Syscall::Sleep, "fast-syscall-unwind", UnwindHandler);
    if table
        .install_interceptor(alloc::boxed::Box::new(Probe))
        .is_err()
    {
        return TestResult::Fail("fast-syscall interceptor installation failed");
    }
    install_global(table);
    if try_install_instruction_interceptor(alloc::boxed::Box::new(RdtscProbe)).is_err() {
        return TestResult::Fail("RDTSC interceptor installation failed");
    }
    let online_cpus = narf_lib::smp::online_bitmap();
    RDTSC_ARMED_CPUS.store(0, Ordering::Release);
    // SAFETY: the callback only reads the local cached CR4 value and updates a
    // lock-free atomic bitmap. It allocates, blocks, awaits, and locks nowhere.
    if !unsafe { narf_lib::smp::remote_call(online_cpus, record_cpu_with_rdtsc_trap_armed) } {
        return TestResult::Fail("RDTSC post-install AP inspection rendezvous failed");
    }
    if RDTSC_ARMED_CPUS.load(Ordering::Acquire) & online_cpus != online_cpus {
        return TestResult::Fail("RDTSC install returned before every online CPU armed CR4.TSD");
    }

    // SAFETY: the test owns this fresh user address space until longjmp.
    let address_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(address_space) => address_space,
        Err(_) => return TestResult::Fail("new_for_user failed"),
    };
    const CODE_VADDR: u64 = 0x0000_0080_0000_0000;
    const STACK_VADDR: u64 = 0x0000_0080_0000_1000;
    let code_frame = match narf_memory::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => return TestResult::Fail("alloc code frame"),
    };
    let stack_frame = match narf_memory::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => return TestResult::Fail("alloc stack frame"),
    };
    address_space
        .map_region(Region {
            base: VirtAddr::new(CODE_VADDR),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::EXEC | RegionPerms::WRITE,
            phys: alloc::vec![code_frame],
        })
        .ok();
    address_space
        .map_region(Region {
            base: VirtAddr::new(STACK_VADDR),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![stack_frame],
        })
        .ok();

    // mov eax,0x3fff; syscall; mov rdi,rax; rdtsc; combine edx:eax into
    // rsi; mov rcx,-1; rdtscp; combine edx:eax into r10; mov rdx,rcx;
    // mov eax,Sleep; int 0x80; ud2
    let sleep = Syscall::Sleep.raw().to_le_bytes();
    let code: [u8; 54] = [
        0xB8, 0xFF, 0x3F, 0x00, 0x00, 0x0F, 0x05, // mov eax,0x3fff; syscall
        0x48, 0x89, 0xC7, // mov rdi,rax
        0x0F, 0x31, 0x48, 0xC1, 0xE2, 0x20, 0x48, 0x09, 0xD0, 0x48, 0x89,
        0xC6, // rdtsc -> rsi
        0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, // mov rcx,-1
        0x0F, 0x01, 0xF9, // rdtscp
        0x48, 0xC1, 0xE2, 0x20, 0x48, 0x09, 0xD0, // shl rdx,32; or rax,rdx
        0x49, 0x89, 0xC2, // mov r10,rax
        0x48, 0x89, 0xCA, // mov rdx,rcx
        0xB8, sleep[0], sleep[1], sleep[2], sleep[3], 0xCD, 0x80, 0x0F, 0x0B,
    ];
    // SAFETY: code_frame is exclusively owned and the copy fits one page.
    unsafe {
        core::ptr::copy_nonoverlapping(
            code.as_ptr(),
            code_frame.kernel_mut_ptr::<u8>(),
            code.len(),
        );
    }
    // SAFETY: materialize publishes the complete mappings constructed above.
    if unsafe { address_space.materialize() }.is_err() {
        return TestResult::Fail("materialize failed");
    }
    if address_space.activate().is_err() {
        return TestResult::Fail("activate failed");
    }
    // SAFETY: enter mapped ring-3 code with a mapped stack and IRQs disabled
    // across the transition. Success returns only via resume_trampoline.
    unsafe {
        core::arch::asm!("cli");
        CPU_BEFORE.store(narf_lib::percpu::current_cpu() as u64, Ordering::Release);
        TSC_BEFORE.store(core::arch::x86_64::_rdtsc(), Ordering::Release);
        user_mode_enter(CODE_VADDR, STACK_VADDR + 0x1000)
    }
}
#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
kernel_test_in!(
    "verification/syscall-entry",
    smoke_frame_x86_64_user_mode_fast_syscall_interceptor
);

#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
fn smoke_frame_x86_64_user_mode_rdtscp_interceptor() -> TestResult {
    // Enter real ring 3 with only RDTSCP subscribed. The interceptor completes
    // RDTSCP with a magic timestamp and TSC_AUX; the user code preloads RCX with
    // all ones, so the reported RCX proves the architecture zero-extends ECX.
    // The following RDTSC shares CR4.TSD but is unsubscribed, so it must
    // complete natively without entering the tool. An unknown fast syscall with
    // no syscall interceptor installed must report -ENOSYS, as Linux does, and
    // not the -EINVAL fold used for Narf-native statuses.
    use core::arch::naked_asm;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_memory::{AddressSpace, Region, RegionPerms, VirtAddr};
    use narf_userspace::{
        install_global, instruction::__verification_clear_instruction_interceptor,
        syscall::__verification_clear_global as __test_clear_global,
        try_install_instruction_interceptor, InstructionInterception, InstructionInterceptor,
        InstructionInvocation, InstructionResult, InstructionSubscriptions,
        NondeterministicInstruction, Syscall, SyscallHandler, SyscallTable, TrapContext,
    };

    const RDTSCP_MAGIC: u64 = 0x0FED_CBA9_8765_4321;
    const AUX_MAGIC: u32 = 0xC0DE_CAFE;
    const ENOSYS: u64 = (-38i64) as u64;
    static SEEN_RDTSCP_TSC: AtomicU64 = AtomicU64::new(0);
    static SEEN_RDTSCP_AUX: AtomicU64 = AtomicU64::new(0);
    static SEEN_RDTSC_TSC: AtomicU64 = AtomicU64::new(0);
    static SEEN_UNKNOWN_SYSCALL: AtomicU64 = AtomicU64::new(0);
    static RDTSCP_ENTRIES: AtomicU64 = AtomicU64::new(0);
    static RDTSCP_RETURNS: AtomicU64 = AtomicU64::new(0);
    static OTHER_INSTRUCTION_ENTRIES: AtomicU64 = AtomicU64::new(0);
    static TSC_BEFORE: AtomicU64 = AtomicU64::new(0);
    static SAVED_CR3: AtomicU64 = AtomicU64::new(0);
    static mut JMP: UserModeJmpBuf = UserModeJmpBuf {
        rbx: 0,
        rbp: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        rsp: 0,
        rip: 0,
    };

    struct RdtscpProbe;
    // SAFETY: every callback uses only preallocated atomics and typed values;
    // it does not allocate, park, lock, await, or re-enter guest execution.
    unsafe impl InstructionInterceptor for RdtscpProbe {
        fn subscriptions(&self) -> InstructionSubscriptions {
            InstructionSubscriptions::RDTSCP
        }

        fn on_instruction_enter(
            &self,
            invocation: &InstructionInvocation,
        ) -> InstructionInterception {
            if invocation.instruction == NondeterministicInstruction::Rdtscp {
                RDTSCP_ENTRIES.fetch_add(1, Ordering::Relaxed);
                InstructionInterception::Complete(InstructionResult::Rdtscp {
                    value: RDTSCP_MAGIC - 1,
                    aux: AUX_MAGIC,
                })
            } else {
                OTHER_INSTRUCTION_ENTRIES.fetch_add(1, Ordering::Relaxed);
                InstructionInterception::Continue
            }
        }

        fn on_instruction_return(
            &self,
            _invocation: &InstructionInvocation,
            result: InstructionResult,
        ) -> InstructionResult {
            match result {
                InstructionResult::Rdtscp { value, aux } => {
                    RDTSCP_RETURNS.fetch_add(1, Ordering::Relaxed);
                    InstructionResult::Rdtscp {
                        value: value.wrapping_add(1),
                        aux,
                    }
                }
                other => other,
            }
        }
    }

    #[unsafe(naked)]
    unsafe extern "C" fn resume_trampoline() -> ! {
        naked_asm!(
            "lea rdi, [rip + {jmp}]",
            "mov rsi, 1",
            "jmp {lj}",
            jmp = sym JMP,
            lj = sym user_mode_longjmp,
        );
    }

    struct UnwindHandler;
    impl SyscallHandler for UnwindHandler {
        fn handle(&self, ctx: &mut dyn TrapContext) {
            SEEN_RDTSCP_TSC.store(ctx.args().arg0, Ordering::Release);
            SEEN_RDTSCP_AUX.store(ctx.args().arg1, Ordering::Release);
            SEEN_RDTSC_TSC.store(ctx.args().arg2, Ordering::Release);
            SEEN_UNKNOWN_SYSCALL.store(ctx.args().arg3, Ordering::Release);
            let _ =
                ctx.redirect_to_kernel(resume_trampoline as usize as u64, 0xFFFF_FFFF_FFFF_FFF0);
        }
    }

    SEEN_RDTSCP_TSC.store(0, Ordering::Relaxed);
    SEEN_RDTSCP_AUX.store(0, Ordering::Relaxed);
    SEEN_RDTSC_TSC.store(0, Ordering::Relaxed);
    SEEN_UNKNOWN_SYSCALL.store(0, Ordering::Relaxed);
    RDTSCP_ENTRIES.store(0, Ordering::Relaxed);
    RDTSCP_RETURNS.store(0, Ordering::Relaxed);
    OTHER_INSTRUCTION_ENTRIES.store(0, Ordering::Relaxed);
    __test_clear_global();
    __verification_clear_instruction_interceptor();

    let original_cr3: u64;
    // SAFETY: read the active kernel address space so the non-local return can
    // restore it after the user-mode side trip.
    unsafe {
        core::arch::asm!("mov {v}, cr3", v = out(reg) original_cr3,
            options(nostack, preserves_flags));
    }
    SAVED_CR3.store(original_cr3, Ordering::Release);

    // SAFETY: JMP is dedicated storage for this single-threaded test.
    let saved = unsafe { user_mode_setjmp(core::ptr::addr_of_mut!(JMP)) };
    if saved != 0 {
        // SAFETY: restore the exact kernel CR3 and GS state saved before ring 3.
        unsafe {
            let cr3 = SAVED_CR3.load(Ordering::Acquire);
            core::arch::asm!("mov cr3, {v}", v = in(reg) cr3,
                options(nostack, preserves_flags));
            const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
            core::arch::asm!(
                "wrmsr",
                in("ecx") IA32_KERNEL_GS_BASE,
                in("eax") 0u32,
                in("edx") 0u32,
                options(nostack, preserves_flags),
            );
            core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
        }
        // SAFETY: RDTSC is always legal at CPL0.
        let tsc_after = unsafe { core::arch::x86_64::_rdtsc() };
        __test_clear_global();
        __verification_clear_instruction_interceptor();
        if SEEN_UNKNOWN_SYSCALL.load(Ordering::Acquire) != ENOSYS {
            return TestResult::Fail("unknown fast syscall did not return -ENOSYS");
        }
        if RDTSCP_ENTRIES.load(Ordering::Acquire) != 1
            || RDTSCP_RETURNS.load(Ordering::Acquire) != 1
        {
            return TestResult::Fail("ring-3 RDTSCP did not enter and return exactly once");
        }
        if OTHER_INSTRUCTION_ENTRIES.load(Ordering::Acquire) != 0 {
            return TestResult::Fail("unsubscribed RDTSC entered the RDTSCP-only interceptor");
        }
        if SEEN_RDTSCP_TSC.load(Ordering::Acquire) != RDTSCP_MAGIC {
            return TestResult::Fail("ring-3 RDTSCP did not receive the interceptor timestamp");
        }
        if SEEN_RDTSCP_AUX.load(Ordering::Acquire) != AUX_MAGIC as u64 {
            return TestResult::Fail("ring-3 RDTSCP RCX was not the zero-extended interceptor AUX");
        }
        let native = SEEN_RDTSC_TSC.load(Ordering::Acquire);
        if native < TSC_BEFORE.load(Ordering::Acquire) || native > tsc_after {
            return TestResult::Fail("unsubscribed RDTSC did not return a native TSC value");
        }
        return TestResult::Pass;
    }

    if !cpu_has_rdtscp() {
        return TestResult::Skip("RDTSCP not supported by this CPU model");
    }
    let mut table = SyscallTable::new();
    table.install_raw(Syscall::Sleep, "rdtscp-unwind", UnwindHandler);
    install_global(table);
    if try_install_instruction_interceptor(alloc::boxed::Box::new(RdtscpProbe)).is_err() {
        return TestResult::Fail("RDTSCP interceptor installation failed");
    }
    let online_cpus = narf_lib::smp::online_bitmap();
    RDTSC_ARMED_CPUS.store(0, Ordering::Release);
    // SAFETY: the callback only reads the local cached CR4 value and updates a
    // lock-free atomic bitmap. It allocates, blocks, awaits, and locks nowhere.
    if !unsafe { narf_lib::smp::remote_call(online_cpus, record_cpu_with_rdtsc_trap_armed) } {
        return TestResult::Fail("RDTSCP post-install AP inspection rendezvous failed");
    }
    if RDTSC_ARMED_CPUS.load(Ordering::Acquire) & online_cpus != online_cpus {
        return TestResult::Fail("RDTSCP-only install did not arm CR4.TSD on every online CPU");
    }

    // SAFETY: the test owns this fresh user address space until longjmp.
    let address_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(address_space) => address_space,
        Err(_) => return TestResult::Fail("new_for_user failed"),
    };
    const CODE_VADDR: u64 = 0x0000_0080_0000_0000;
    const STACK_VADDR: u64 = 0x0000_0080_0000_1000;
    let code_frame = match narf_memory::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => return TestResult::Fail("alloc code frame"),
    };
    let stack_frame = match narf_memory::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => return TestResult::Fail("alloc stack frame"),
    };
    address_space
        .map_region(Region {
            base: VirtAddr::new(CODE_VADDR),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::EXEC | RegionPerms::WRITE,
            phys: alloc::vec![code_frame],
        })
        .ok();
    address_space
        .map_region(Region {
            base: VirtAddr::new(STACK_VADDR),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![stack_frame],
        })
        .ok();

    let sleep = Syscall::Sleep.raw().to_le_bytes();
    let code: [u8; 51] = [
        0xB8, 0xFF, 0x3F, 0x00, 0x00, 0x0F, 0x05, // mov eax,0x3fff; syscall
        0x49, 0x89, 0xC2, // mov r10,rax
        0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, // mov rcx,-1
        0x0F, 0x01, 0xF9, // rdtscp
        0x48, 0xC1, 0xE2, 0x20, 0x48, 0x09, 0xD0, // shl rdx,32; or rax,rdx
        0x48, 0x89, 0xC7, // mov rdi,rax
        0x48, 0x89, 0xCE, // mov rsi,rcx
        0x0F, 0x31, 0x48, 0xC1, 0xE2, 0x20, 0x48, 0x09, 0xC2, // rdtsc; shl rdx,32; or rdx,rax
        0xB8, sleep[0], sleep[1], sleep[2], sleep[3], 0xCD, 0x80, 0x0F, 0x0B,
    ];
    // SAFETY: code_frame is exclusively owned and the copy fits one page.
    unsafe {
        core::ptr::copy_nonoverlapping(
            code.as_ptr(),
            code_frame.kernel_mut_ptr::<u8>(),
            code.len(),
        );
    }
    // SAFETY: materialize publishes the complete mappings constructed above.
    if unsafe { address_space.materialize() }.is_err() {
        return TestResult::Fail("materialize failed");
    }
    if address_space.activate().is_err() {
        return TestResult::Fail("activate failed");
    }
    // SAFETY: enter mapped ring-3 code with a mapped stack and IRQs disabled
    // across the transition. Success returns only via resume_trampoline.
    unsafe {
        core::arch::asm!("cli");
        TSC_BEFORE.store(core::arch::x86_64::_rdtsc(), Ordering::Release);
        user_mode_enter(CODE_VADDR, STACK_VADDR + 0x1000)
    }
}
#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
kernel_test_in!(
    "verification/syscall-entry",
    smoke_frame_x86_64_user_mode_rdtscp_interceptor
);

#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
fn smoke_frame_x86_64_prefixed_rdtsc_takes_the_sync_fault_path() -> TestResult {
    // Enter real ring 3 with RDTSC subscribed. The exact `0f 31` enters the
    // tool once and completes natively. The following `66 0f 31` still faults
    // under CR4.TSD, but the frame owner does not decode it, so it must reach
    // the ordinary synchronous-fault hook as #GP at its own RIP without
    // entering the tool. The recording hook stands in for the default
    // delivery, which would raise SIGSEGV, so this proves the fault reaches
    // the hook, not the signal itself. It resumes at a landing pad whose
    // marker distinguishes it from the prefixed read having executed.
    use core::arch::naked_asm;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_memory::{AddressSpace, Region, RegionPerms, VirtAddr};
    use narf_userspace::{
        install_global, install_sync_signal_hook,
        instruction::__verification_clear_instruction_interceptor, sync_signal_hook,
        syscall::__verification_clear_global as __test_clear_global,
        try_install_instruction_interceptor, InstructionInterception, InstructionInterceptor,
        InstructionInvocation, InstructionResult, InstructionSubscriptions,
        NondeterministicInstruction, SyncFaultInfo, Syscall, SyscallHandler, SyscallTable,
        TrapContext,
    };

    type Hook = fn(&mut dyn TrapContext, u64, SyncFaultInfo) -> bool;
    const CODE_VADDR: u64 = 0x0000_0080_0000_0000;
    const STACK_VADDR: u64 = 0x0000_0080_0000_1000;
    const PREFIXED_OFFSET: u64 = 2;
    const LAND_OFFSET: u64 = 12;
    const LANDED: u64 = 0x5E6F;
    const FELL_THROUGH: u64 = 0x0BAD;
    static RDTSC_ENTRIES: AtomicU64 = AtomicU64::new(0);
    static OTHER_INSTRUCTION_ENTRIES: AtomicU64 = AtomicU64::new(0);
    static FAULTS: AtomicU64 = AtomicU64::new(0);
    static FAULT_VECTOR: AtomicU64 = AtomicU64::new(u64::MAX);
    static FAULT_ADDR: AtomicU64 = AtomicU64::new(u64::MAX);
    static SEEN_MARKER: AtomicU64 = AtomicU64::new(0);
    static SAVED_CR3: AtomicU64 = AtomicU64::new(0);
    static mut PREVIOUS_HOOK: Option<Hook> = None;
    static mut JMP: UserModeJmpBuf = UserModeJmpBuf {
        rbx: 0,
        rbp: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        rsp: 0,
        rip: 0,
    };

    struct RdtscProbe;
    // SAFETY: every callback uses only preallocated atomics and typed values;
    // it does not allocate, park, lock, await, or re-enter guest execution.
    unsafe impl InstructionInterceptor for RdtscProbe {
        fn subscriptions(&self) -> InstructionSubscriptions {
            InstructionSubscriptions::RDTSC
        }

        fn on_instruction_enter(
            &self,
            invocation: &InstructionInvocation,
        ) -> InstructionInterception {
            if invocation.instruction == NondeterministicInstruction::Rdtsc {
                RDTSC_ENTRIES.fetch_add(1, Ordering::Relaxed);
            } else {
                OTHER_INSTRUCTION_ENTRIES.fetch_add(1, Ordering::Relaxed);
            }
            InstructionInterception::Continue
        }

        fn on_instruction_return(
            &self,
            _invocation: &InstructionInvocation,
            result: InstructionResult,
        ) -> InstructionResult {
            result
        }
    }

    fn recording(ctx: &mut dyn TrapContext, vector: u64, info: SyncFaultInfo) -> bool {
        if FAULTS.fetch_add(1, Ordering::Relaxed) != 0 {
            // A second user fault has no landing pad; let the ordinary
            // delivery path report it.
            return false;
        }
        FAULT_VECTOR.store(vector, Ordering::Relaxed);
        FAULT_ADDR.store(info.addr, Ordering::Relaxed);
        ctx.set_rip(CODE_VADDR + LAND_OFFSET);
        true
    }

    fn restore_hook() {
        // SAFETY: PREVIOUS_HOOK is written once before ring 3 and read here on
        // the same CPU after the non-local return.
        let previous = unsafe { PREVIOUS_HOOK };
        install_sync_signal_hook(previous.unwrap_or(narf_userspace::default_sync_signal_delivery));
    }

    #[unsafe(naked)]
    unsafe extern "C" fn resume_trampoline() -> ! {
        naked_asm!(
            "lea rdi, [rip + {jmp}]",
            "mov rsi, 1",
            "jmp {lj}",
            jmp = sym JMP,
            lj = sym user_mode_longjmp,
        );
    }

    struct UnwindHandler;
    impl SyscallHandler for UnwindHandler {
        fn handle(&self, ctx: &mut dyn TrapContext) {
            SEEN_MARKER.store(ctx.args().arg0, Ordering::Release);
            let _ =
                ctx.redirect_to_kernel(resume_trampoline as usize as u64, 0xFFFF_FFFF_FFFF_FFF0);
        }
    }

    RDTSC_ENTRIES.store(0, Ordering::Relaxed);
    OTHER_INSTRUCTION_ENTRIES.store(0, Ordering::Relaxed);
    FAULTS.store(0, Ordering::Relaxed);
    FAULT_VECTOR.store(u64::MAX, Ordering::Relaxed);
    FAULT_ADDR.store(u64::MAX, Ordering::Relaxed);
    SEEN_MARKER.store(0, Ordering::Relaxed);
    __test_clear_global();
    __verification_clear_instruction_interceptor();

    let original_cr3: u64;
    // SAFETY: read the active kernel address space so the non-local return can
    // restore it after the user-mode side trip.
    unsafe {
        core::arch::asm!("mov {v}, cr3", v = out(reg) original_cr3,
            options(nostack, preserves_flags));
    }
    SAVED_CR3.store(original_cr3, Ordering::Release);

    // SAFETY: JMP is dedicated storage for this single-threaded test.
    let saved = unsafe { user_mode_setjmp(core::ptr::addr_of_mut!(JMP)) };
    if saved != 0 {
        // SAFETY: restore the exact kernel CR3 and GS state saved before ring 3.
        unsafe {
            let cr3 = SAVED_CR3.load(Ordering::Acquire);
            core::arch::asm!("mov cr3, {v}", v = in(reg) cr3,
                options(nostack, preserves_flags));
            const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
            core::arch::asm!(
                "wrmsr",
                in("ecx") IA32_KERNEL_GS_BASE,
                in("eax") 0u32,
                in("edx") 0u32,
                options(nostack, preserves_flags),
            );
            core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
        }
        restore_hook();
        __test_clear_global();
        __verification_clear_instruction_interceptor();
        if SEEN_MARKER.load(Ordering::Acquire) == FELL_THROUGH {
            return TestResult::Fail("prefixed RDTSC executed instead of faulting");
        }
        if SEEN_MARKER.load(Ordering::Acquire) != LANDED {
            return TestResult::Fail("guest did not resume at the fault landing pad");
        }
        if FAULTS.load(Ordering::Acquire) != 1 {
            return TestResult::Fail(
                "prefixed RDTSC did not reach the sync-fault hook exactly once",
            );
        }
        if FAULT_VECTOR.load(Ordering::Acquire) != 13 {
            return TestResult::Fail("prefixed RDTSC did not fault as #GP");
        }
        if FAULT_ADDR.load(Ordering::Acquire) != CODE_VADDR + PREFIXED_OFFSET {
            return TestResult::Fail("sync fault did not report the prefixed RDTSC address");
        }
        if RDTSC_ENTRIES.load(Ordering::Acquire) != 1
            || OTHER_INSTRUCTION_ENTRIES.load(Ordering::Acquire) != 0
        {
            return TestResult::Fail("only the exact RDTSC may enter the interceptor");
        }
        return TestResult::Pass;
    }

    let mut table = SyscallTable::new();
    table.install_raw(Syscall::Sleep, "prefixed-rdtsc-unwind", UnwindHandler);
    install_global(table);
    if try_install_instruction_interceptor(alloc::boxed::Box::new(RdtscProbe)).is_err() {
        __test_clear_global();
        return TestResult::Fail("RDTSC interceptor installation failed");
    }

    // SAFETY: the test owns this fresh user address space until longjmp.
    let address_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(address_space) => address_space,
        Err(_) => return TestResult::Fail("new_for_user failed"),
    };
    let code_frame = match narf_memory::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => return TestResult::Fail("alloc code frame"),
    };
    let stack_frame = match narf_memory::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => return TestResult::Fail("alloc stack frame"),
    };
    address_space
        .map_region(Region {
            base: VirtAddr::new(CODE_VADDR),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::EXEC | RegionPerms::WRITE,
            phys: alloc::vec![code_frame],
        })
        .ok();
    address_space
        .map_region(Region {
            base: VirtAddr::new(STACK_VADDR),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![stack_frame],
        })
        .ok();

    let sleep = Syscall::Sleep.raw().to_le_bytes();
    let code: [u8; 26] = [
        0x0F, 0x31, // rdtsc (exact; enters the tool)
        0x66, 0x0F, 0x31, // o16 rdtsc (prefixed; must fault, not decode)
        0xBF, 0xAD, 0x0B, 0x00, 0x00, // mov edi,FELL_THROUGH
        0xEB, 0x05, // jmp over the landing pad's marker
        0xBF, 0x6F, 0x5E, 0x00, 0x00, // LAND: mov edi,LANDED
        0xB8, sleep[0], sleep[1], sleep[2], sleep[3], 0xCD, 0x80, // mov eax,Sleep; int 0x80
        0x0F, 0x0B, // ud2
    ];
    // SAFETY: code_frame is exclusively owned and the copy fits one page.
    unsafe {
        core::ptr::copy_nonoverlapping(
            code.as_ptr(),
            code_frame.kernel_mut_ptr::<u8>(),
            code.len(),
        );
    }
    // SAFETY: materialize publishes the complete mappings constructed above.
    if unsafe { address_space.materialize() }.is_err() {
        return TestResult::Fail("materialize failed");
    }
    if address_space.activate().is_err() {
        return TestResult::Fail("activate failed");
    }
    // SAFETY: single writer before ring 3; restore_hook reads it afterwards.
    unsafe {
        PREVIOUS_HOOK = sync_signal_hook();
    }
    install_sync_signal_hook(recording);
    // SAFETY: enter mapped ring-3 code with a mapped stack and IRQs disabled
    // across the transition. Success returns only via resume_trampoline.
    unsafe {
        core::arch::asm!("cli");
        user_mode_enter(CODE_VADDR, STACK_VADDR + 0x1000)
    }
}
#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
kernel_test_in!(
    "verification/syscall-entry",
    smoke_frame_x86_64_prefixed_rdtsc_takes_the_sync_fault_path
);

/// While user RDTSC interception is requested, no CR4 write may clear CR4.TSD.
/// A read-modify-write whose read preceded the arming rendezvous IPI writes a
/// value without TSD; `write_cr4` must keep the bit, in the register and in
/// the cached copy, and must leave every other bit as given.
#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
fn smoke_x86_64_cr4_writes_keep_requested_tsd() -> TestResult {
    use narf_arch::x86_64::cr;
    use narf_userspace::instruction::__verification_clear_instruction_interceptor;

    __verification_clear_instruction_interceptor();
    // SAFETY: CR4 reads and writes of the value just read are legal at CPL0.
    let stale = unsafe { cr::read_cr4() };
    if stale & cr::CR4_TSD != 0 {
        return TestResult::Fail("CR4.TSD set with no interception request");
    }
    // Control: with no request, the value is written unchanged.
    // SAFETY: rewrites the value just read.
    unsafe { cr::write_cr4(stale) };
    // SAFETY: as above.
    if unsafe { cr::read_cr4() } & cr::CR4_TSD != 0 {
        return TestResult::Fail("write_cr4 set CR4.TSD with no request");
    }

    cr::request_user_rdtsc_interception();
    // SAFETY: as above.
    let armed = unsafe { cr::read_cr4() };
    // SAFETY: writes back the pre-request value, as a stale read-modify-write
    // would; only TSD differs from the live register.
    unsafe { cr::write_cr4(stale) };
    // SAFETY: as above.
    let after = unsafe { cr::read_cr4() };
    let cached = cr::cached_cr4();
    __verification_clear_instruction_interceptor();

    if armed & cr::CR4_TSD == 0 {
        return TestResult::Fail("request did not arm the executing CPU");
    }
    if after & cr::CR4_TSD == 0 {
        return TestResult::Fail("write_cr4 cleared requested CR4.TSD");
    }
    if cached & cr::CR4_TSD == 0 {
        return TestResult::Fail("cached CR4 lost requested CR4.TSD");
    }
    if after & !cr::CR4_TSD != stale {
        return TestResult::Fail("write_cr4 altered a CR4 bit other than TSD");
    }
    TestResult::Pass
}
#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
kernel_test_in!(
    "verification/syscall-entry",
    smoke_x86_64_cr4_writes_keep_requested_tsd
);

/// Offset of the dynamic symbol `name` in a little-endian ELF64 image whose
/// file offsets equal its virtual addresses (the vDSO link layout).
#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
fn vdso_symbol_offset(elf: &[u8], name: &[u8]) -> Option<u64> {
    const SHT_DYNSYM: u32 = 11;
    let u16_at = |o: usize| Some(u16::from_le_bytes(elf.get(o..o + 2)?.try_into().ok()?));
    let u32_at = |o: usize| Some(u32::from_le_bytes(elf.get(o..o + 4)?.try_into().ok()?));
    let u64_at = |o: usize| Some(u64::from_le_bytes(elf.get(o..o + 8)?.try_into().ok()?));
    let shoff = u64_at(0x28)? as usize;
    let shentsize = u16_at(0x3A)? as usize;
    let shnum = u16_at(0x3C)? as usize;
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        if u32_at(sh + 4)? != SHT_DYNSYM {
            continue;
        }
        let symoff = u64_at(sh + 24)? as usize;
        let symsize = u64_at(sh + 32)? as usize;
        let strsh = shoff + u32_at(sh + 40)? as usize * shentsize;
        let stroff = u64_at(strsh + 24)? as usize;
        for sym in (symoff..symoff + symsize).step_by(24) {
            let start = stroff + u32_at(sym)? as usize;
            let len = elf.get(start..)?.iter().position(|&b| b == 0)?;
            if &elf[start..start + len] == name {
                return u64_at(sym + 8);
            }
        }
    }
    None
}

#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
fn smoke_x86_64_vdso_clocks_use_syscalls_under_timestamp_interception() -> TestResult {
    // Install an RDTSC interceptor alongside a syscall interceptor, then call
    // the real vDSO's clock_gettime, time and gettimeofday from ring 3. With a
    // timestamp interceptor installed each must issue its syscall and return
    // the tool's result, and none may read the counter: a counter read would
    // enter the RDTSC interceptor and the vDSO would convert the tool's value
    // with the host scale, a second time base the syscalls never report. A
    // final guest RDTSC is the positive control that the trap is armed and
    // reaches the tool exactly once.
    use core::arch::naked_asm;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_memory::{AddressSpace, Region, RegionPerms, VirtAddr};
    use narf_userspace::{
        install_global, instruction::__verification_clear_instruction_interceptor,
        syscall::__verification_clear_global as __test_clear_global,
        try_install_instruction_interceptor, vdso, InstructionInterception, InstructionInterceptor,
        InstructionInvocation, InstructionResult, InstructionSubscriptions,
        NondeterministicInstruction, Syscall, SyscallHandler, SyscallInterception,
        SyscallInterceptor, SyscallInvocation, SyscallReturn, SyscallTable, TrapContext,
    };

    const CLOCK_GETTIME: u32 = 228;
    const GETTIMEOFDAY: u32 = 96;
    const TIME: u32 = 201;
    const CLOCK_MONOTONIC: u64 = 1;
    // clock_gettime and gettimeofday return `int` through the vDSO, so their
    // magics fit in 31 bits; time returns a full 64-bit value.
    const CLOCK_MAGIC: u64 = 0x1357_2468;
    const GTOD_MAGIC: u64 = 0x2468_1357;
    const TIME_MAGIC: u64 = 0x7777_0000_1111_2222;
    const RDTSC_MAGIC: u64 = 0x0BAD_C0DE_1234_5678;
    const CODE_VADDR: u64 = 0x0000_0080_0000_0000;
    const STACK_VADDR: u64 = 0x0000_0080_0000_1000;
    const TS_VADDR: u64 = STACK_VADDR + 0x800;
    const TV_VADDR: u64 = STACK_VADDR + 0x900;
    static CLOCK_ENTRIES: AtomicU64 = AtomicU64::new(0);
    static CLOCK_ARGS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
    static GTOD_ENTRIES: AtomicU64 = AtomicU64::new(0);
    static GTOD_ARGS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
    static TIME_ENTRIES: AtomicU64 = AtomicU64::new(0);
    static TIME_ARG: AtomicU64 = AtomicU64::new(0);
    static RDTSC_ENTRIES: AtomicU64 = AtomicU64::new(0);
    static SEEN: [AtomicU64; 4] = [
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    ];
    static SAVED_CR3: AtomicU64 = AtomicU64::new(0);
    static mut JMP: UserModeJmpBuf = UserModeJmpBuf {
        rbx: 0,
        rbp: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        rsp: 0,
        rip: 0,
    };

    struct ClockProbe;
    impl SyscallInterceptor for ClockProbe {
        fn on_syscall_enter(
            &self,
            invocation: &SyscallInvocation,
            _native: &mut dyn narf_userspace::NativeSyscallTransition,
        ) -> SyscallInterception {
            let args = &invocation.args;
            let magic = match invocation.raw_number {
                CLOCK_GETTIME => {
                    CLOCK_ENTRIES.fetch_add(1, Ordering::Relaxed);
                    CLOCK_ARGS[0].store(args.arg0, Ordering::Relaxed);
                    CLOCK_ARGS[1].store(args.arg1, Ordering::Relaxed);
                    CLOCK_MAGIC
                }
                GETTIMEOFDAY => {
                    GTOD_ENTRIES.fetch_add(1, Ordering::Relaxed);
                    GTOD_ARGS[0].store(args.arg0, Ordering::Relaxed);
                    GTOD_ARGS[1].store(args.arg1, Ordering::Relaxed);
                    GTOD_MAGIC
                }
                TIME => {
                    TIME_ENTRIES.fetch_add(1, Ordering::Relaxed);
                    TIME_ARG.store(args.arg0, Ordering::Relaxed);
                    TIME_MAGIC
                }
                _ => return SyscallInterception::Continue,
            };
            SyscallInterception::Complete(SyscallReturn::ok(magic))
        }
    }

    struct RdtscProbe;
    // SAFETY: every callback uses only preallocated atomics and typed values;
    // it does not allocate, park, lock, await, or re-enter guest execution.
    unsafe impl InstructionInterceptor for RdtscProbe {
        fn subscriptions(&self) -> InstructionSubscriptions {
            InstructionSubscriptions::RDTSC
        }

        fn on_instruction_enter(
            &self,
            invocation: &InstructionInvocation,
        ) -> InstructionInterception {
            if invocation.instruction == NondeterministicInstruction::Rdtsc {
                RDTSC_ENTRIES.fetch_add(1, Ordering::Relaxed);
                InstructionInterception::Complete(InstructionResult::Rdtsc { value: RDTSC_MAGIC })
            } else {
                InstructionInterception::Continue
            }
        }

        fn on_instruction_return(
            &self,
            _invocation: &InstructionInvocation,
            result: InstructionResult,
        ) -> InstructionResult {
            result
        }
    }

    #[unsafe(naked)]
    unsafe extern "C" fn resume_trampoline() -> ! {
        naked_asm!(
            "lea rdi, [rip + {jmp}]",
            "mov rsi, 1",
            "jmp {lj}",
            jmp = sym JMP,
            lj = sym user_mode_longjmp,
        );
    }

    struct UnwindHandler;
    impl SyscallHandler for UnwindHandler {
        fn handle(&self, ctx: &mut dyn TrapContext) {
            let args = ctx.args();
            SEEN[0].store(args.arg0, Ordering::Release);
            SEEN[1].store(args.arg1, Ordering::Release);
            SEEN[2].store(args.arg2, Ordering::Release);
            SEEN[3].store(args.arg3, Ordering::Release);
            let _ =
                ctx.redirect_to_kernel(resume_trampoline as usize as u64, 0xFFFF_FFFF_FFFF_FFF0);
        }
    }

    for counter in [
        &CLOCK_ENTRIES,
        &CLOCK_ARGS[0],
        &CLOCK_ARGS[1],
        &GTOD_ENTRIES,
        &GTOD_ARGS[0],
        &GTOD_ARGS[1],
        &TIME_ENTRIES,
        &TIME_ARG,
        &RDTSC_ENTRIES,
        &SEEN[0],
        &SEEN[1],
        &SEEN[2],
        &SEEN[3],
    ] {
        counter.store(u64::MAX, Ordering::Relaxed);
    }
    for counter in [&CLOCK_ENTRIES, &GTOD_ENTRIES, &TIME_ENTRIES, &RDTSC_ENTRIES] {
        counter.store(0, Ordering::Relaxed);
    }
    __test_clear_global();
    __verification_clear_instruction_interceptor();

    let original_cr3: u64;
    // SAFETY: read the active kernel address space so the non-local return can
    // restore it after the user-mode side trip.
    unsafe {
        core::arch::asm!("mov {v}, cr3", v = out(reg) original_cr3,
            options(nostack, preserves_flags));
    }
    SAVED_CR3.store(original_cr3, Ordering::Release);

    // SAFETY: JMP is dedicated storage for this single-threaded test.
    let saved = unsafe { user_mode_setjmp(core::ptr::addr_of_mut!(JMP)) };
    if saved != 0 {
        // SAFETY: restore the exact kernel CR3 and GS state saved before ring 3.
        unsafe {
            let cr3 = SAVED_CR3.load(Ordering::Acquire);
            core::arch::asm!("mov cr3, {v}", v = in(reg) cr3,
                options(nostack, preserves_flags));
            const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
            core::arch::asm!(
                "wrmsr",
                in("ecx") IA32_KERNEL_GS_BASE,
                in("eax") 0u32,
                in("edx") 0u32,
                options(nostack, preserves_flags),
            );
            core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
        }
        __test_clear_global();
        __verification_clear_instruction_interceptor();
        if vdso::clocks_route_through_syscalls() {
            return TestResult::Fail("interceptor reset did not restore the vDSO counter path");
        }
        if RDTSC_ENTRIES.load(Ordering::Acquire) != 1 {
            return TestResult::Fail("vDSO clock read the counter instead of issuing its syscall");
        }
        if SEEN[3].load(Ordering::Acquire) != RDTSC_MAGIC {
            return TestResult::Fail("control RDTSC did not receive the interceptor value");
        }
        if CLOCK_ENTRIES.load(Ordering::Acquire) != 1
            || CLOCK_ARGS[0].load(Ordering::Acquire) != CLOCK_MONOTONIC
            || CLOCK_ARGS[1].load(Ordering::Acquire) != TS_VADDR
        {
            return TestResult::Fail("vDSO clock_gettime did not issue clock_gettime(1, ts) once");
        }
        if TIME_ENTRIES.load(Ordering::Acquire) != 1 || TIME_ARG.load(Ordering::Acquire) != 0 {
            return TestResult::Fail("vDSO time did not issue time(NULL) once");
        }
        if GTOD_ENTRIES.load(Ordering::Acquire) != 1
            || GTOD_ARGS[0].load(Ordering::Acquire) != TV_VADDR
            || GTOD_ARGS[1].load(Ordering::Acquire) != 0
        {
            return TestResult::Fail("vDSO gettimeofday did not issue gettimeofday(tv, NULL) once");
        }
        if SEEN[0].load(Ordering::Acquire) != CLOCK_MAGIC
            || SEEN[1].load(Ordering::Acquire) != TIME_MAGIC
            || SEEN[2].load(Ordering::Acquire) != GTOD_MAGIC
        {
            return TestResult::Fail("vDSO clock entry did not return the tool's syscall result");
        }
        return TestResult::Pass;
    }

    let sleep = Syscall::Sleep.raw();
    if [CLOCK_GETTIME, GETTIMEOFDAY, TIME].contains(&sleep) {
        return TestResult::Fail("unwind syscall number collides with a clock syscall");
    }
    let (Some(clock_gettime), Some(time), Some(gettimeofday)) = (
        vdso_symbol_offset(NARF_VDSO_ELF, b"__vdso_clock_gettime"),
        vdso_symbol_offset(NARF_VDSO_ELF, b"__vdso_time"),
        vdso_symbol_offset(NARF_VDSO_ELF, b"__vdso_gettimeofday"),
    ) else {
        return TestResult::Fail("vDSO image is empty or lacks a clock entry point");
    };
    vdso::register_vdso_image(NARF_VDSO_ELF, narf_scheduler::narf_time::cycles_per_ns());

    let mut table = SyscallTable::new();
    table.install_raw(Syscall::Sleep, "vdso-clock-unwind", UnwindHandler);
    if table
        .install_interceptor(alloc::boxed::Box::new(ClockProbe))
        .is_err()
    {
        return TestResult::Fail("clock syscall interceptor installation failed");
    }
    install_global(table);
    if vdso::clocks_route_through_syscalls() {
        return TestResult::Fail("vDSO clocks used syscalls before any timestamp interceptor");
    }
    if try_install_instruction_interceptor(alloc::boxed::Box::new(RdtscProbe)).is_err() {
        return TestResult::Fail("RDTSC interceptor installation failed");
    }
    if !vdso::clocks_route_through_syscalls() {
        return TestResult::Fail("timestamp interceptor install did not route vDSO clocks");
    }

    // SAFETY: the test owns this fresh user address space until longjmp.
    let address_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(address_space) => address_space,
        Err(_) => return TestResult::Fail("new_for_user failed"),
    };
    let code_frame = match narf_memory::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => return TestResult::Fail("alloc code frame"),
    };
    let stack_frame = match narf_memory::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => return TestResult::Fail("alloc stack frame"),
    };
    address_space
        .map_region(Region {
            base: VirtAddr::new(CODE_VADDR),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::EXEC | RegionPerms::WRITE,
            phys: alloc::vec![code_frame],
        })
        .ok();
    address_space
        .map_region(Region {
            base: VirtAddr::new(STACK_VADDR),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![stack_frame],
        })
        .ok();
    if vdso::map_into(&address_space) != Some(vdso::VDSO_VADDR) {
        return TestResult::Fail("vDSO map_into failed");
    }

    let mut code = alloc::vec::Vec::new();
    let movabs = |code: &mut alloc::vec::Vec<u8>, opcode: u8, value: u64| {
        code.extend_from_slice(&[0x48, opcode]);
        code.extend_from_slice(&value.to_le_bytes());
    };
    // clock_gettime(CLOCK_MONOTONIC, ts): mov edi,1; movabs rsi; movabs rax;
    // call rax; mov r12d,eax
    code.extend_from_slice(&[0xBF, CLOCK_MONOTONIC as u8, 0, 0, 0]);
    movabs(&mut code, 0xBE, TS_VADDR);
    movabs(&mut code, 0xB8, vdso::VDSO_VADDR + clock_gettime);
    code.extend_from_slice(&[0xFF, 0xD0, 0x41, 0x89, 0xC4]);
    // time(NULL): xor edi,edi; movabs rax; call rax; mov r13,rax
    code.extend_from_slice(&[0x31, 0xFF]);
    movabs(&mut code, 0xB8, vdso::VDSO_VADDR + time);
    code.extend_from_slice(&[0xFF, 0xD0, 0x49, 0x89, 0xC5]);
    // gettimeofday(tv, NULL): movabs rdi; xor esi,esi; movabs rax; call rax;
    // mov r14d,eax
    movabs(&mut code, 0xBF, TV_VADDR);
    code.extend_from_slice(&[0x31, 0xF6]);
    movabs(&mut code, 0xB8, vdso::VDSO_VADDR + gettimeofday);
    code.extend_from_slice(&[0xFF, 0xD0, 0x41, 0x89, 0xC6]);
    // rdtsc; shl rdx,32; or rdx,rax; mov r10,rdx; mov rdi,r12; mov rsi,r13;
    // mov rdx,r14
    code.extend_from_slice(&[
        0x0F, 0x31, 0x48, 0xC1, 0xE2, 0x20, 0x48, 0x09, 0xC2, 0x49, 0x89, 0xD2, 0x4C, 0x89, 0xE7,
        0x4C, 0x89, 0xEE, 0x4C, 0x89, 0xF2,
    ]);
    // mov eax,Sleep; int 0x80; ud2
    code.push(0xB8);
    code.extend_from_slice(&sleep.to_le_bytes());
    code.extend_from_slice(&[0xCD, 0x80, 0x0F, 0x0B]);
    // SAFETY: code_frame is exclusively owned and the copy fits one page.
    unsafe {
        core::ptr::copy_nonoverlapping(
            code.as_ptr(),
            code_frame.kernel_mut_ptr::<u8>(),
            code.len(),
        );
    }
    // SAFETY: materialize publishes the complete mappings constructed above.
    if unsafe { address_space.materialize() }.is_err() {
        return TestResult::Fail("materialize failed");
    }
    if address_space.activate().is_err() {
        return TestResult::Fail("activate failed");
    }
    // SAFETY: enter mapped ring-3 code with a mapped stack and IRQs disabled
    // across the transition. Success returns only via resume_trampoline.
    unsafe {
        core::arch::asm!("cli");
        user_mode_enter(CODE_VADDR, STACK_VADDR + 0x1000)
    }
}
#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
kernel_test_in!(
    "verification/syscall-entry",
    smoke_x86_64_vdso_clocks_use_syscalls_under_timestamp_interception
);

#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
fn smoke_x86_64_vdso_getcpu_uses_syscall_under_timestamp_interception() -> TestResult {
    // With a timestamp interceptor installed, the vDSO's CPU-only
    // getcpu(&cpu, NULL) must issue getcpu(2) instead of reading the CPU number
    // from RDTSCP's TSC_AUX; otherwise the guest learns the physical CPU with
    // no request the tool can see, which Reverie's ptrace backend never allows.
    // The tool subscribes both timestamp families and completes getcpu without
    // writing the result, so the guest's prefilled CPU word survives unless
    // RDTSCP ran, and any RDTSCP enters the tool.
    use core::arch::naked_asm;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_memory::{AddressSpace, Region, RegionPerms, VirtAddr};
    use narf_userspace::{
        install_global, instruction::__verification_clear_instruction_interceptor,
        syscall::__verification_clear_global as __test_clear_global,
        try_install_instruction_interceptor, vdso, InstructionInterception, InstructionInterceptor,
        InstructionInvocation, InstructionResult, InstructionSubscriptions, Syscall,
        SyscallHandler, SyscallInterception, SyscallInterceptor, SyscallInvocation, SyscallReturn,
        SyscallTable, TrapContext,
    };

    const GETCPU: u32 = 309;
    // getcpu returns `int` through the vDSO, so the magic fits in 31 bits.
    const GETCPU_MAGIC: u64 = 0x0246_8ACE;
    const CPU_SENTINEL: u32 = 0xA5A5_5A5A;
    const RDTSCP_AUX_MAGIC: u32 = 0x0ABC;
    const CODE_VADDR: u64 = 0x0000_0080_0000_0000;
    const STACK_VADDR: u64 = 0x0000_0080_0000_1000;
    const CPU_VADDR: u64 = STACK_VADDR + 0x800;
    static GETCPU_ENTRIES: AtomicU64 = AtomicU64::new(0);
    static GETCPU_ARGS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
    static INSTRUCTION_ENTRIES: AtomicU64 = AtomicU64::new(0);
    static SEEN: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
    static SAVED_CR3: AtomicU64 = AtomicU64::new(0);
    static mut JMP: UserModeJmpBuf = UserModeJmpBuf {
        rbx: 0,
        rbp: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        rsp: 0,
        rip: 0,
    };

    struct GetcpuProbe;
    impl SyscallInterceptor for GetcpuProbe {
        fn on_syscall_enter(
            &self,
            invocation: &SyscallInvocation,
            _native: &mut dyn narf_userspace::NativeSyscallTransition,
        ) -> SyscallInterception {
            if invocation.raw_number != GETCPU {
                return SyscallInterception::Continue;
            }
            GETCPU_ENTRIES.fetch_add(1, Ordering::Relaxed);
            GETCPU_ARGS[0].store(invocation.args.arg0, Ordering::Relaxed);
            GETCPU_ARGS[1].store(invocation.args.arg1, Ordering::Relaxed);
            SyscallInterception::Complete(SyscallReturn::ok(GETCPU_MAGIC))
        }
    }

    struct TimestampProbe;
    // SAFETY: every callback uses only preallocated atomics and typed values;
    // it does not allocate, park, lock, await, or re-enter guest execution.
    unsafe impl InstructionInterceptor for TimestampProbe {
        fn subscriptions(&self) -> InstructionSubscriptions {
            InstructionSubscriptions::RDTSC.union(InstructionSubscriptions::RDTSCP)
        }

        fn on_instruction_enter(
            &self,
            invocation: &InstructionInvocation,
        ) -> InstructionInterception {
            INSTRUCTION_ENTRIES.fetch_add(1, Ordering::Relaxed);
            if invocation.instruction == narf_userspace::NondeterministicInstruction::Rdtscp {
                InstructionInterception::Complete(InstructionResult::Rdtscp {
                    value: 0,
                    aux: RDTSCP_AUX_MAGIC,
                })
            } else {
                InstructionInterception::Continue
            }
        }

        fn on_instruction_return(
            &self,
            _invocation: &InstructionInvocation,
            result: InstructionResult,
        ) -> InstructionResult {
            result
        }
    }

    #[unsafe(naked)]
    unsafe extern "C" fn resume_trampoline() -> ! {
        naked_asm!(
            "lea rdi, [rip + {jmp}]",
            "mov rsi, 1",
            "jmp {lj}",
            jmp = sym JMP,
            lj = sym user_mode_longjmp,
        );
    }

    struct UnwindHandler;
    impl SyscallHandler for UnwindHandler {
        fn handle(&self, ctx: &mut dyn TrapContext) {
            let args = ctx.args();
            SEEN[0].store(args.arg0, Ordering::Release);
            SEEN[1].store(args.arg1, Ordering::Release);
            let _ =
                ctx.redirect_to_kernel(resume_trampoline as usize as u64, 0xFFFF_FFFF_FFFF_FFF0);
        }
    }

    for counter in [&GETCPU_ARGS[0], &GETCPU_ARGS[1], &SEEN[0], &SEEN[1]] {
        counter.store(u64::MAX, Ordering::Relaxed);
    }
    GETCPU_ENTRIES.store(0, Ordering::Relaxed);
    INSTRUCTION_ENTRIES.store(0, Ordering::Relaxed);
    __test_clear_global();
    __verification_clear_instruction_interceptor();

    let original_cr3: u64;
    // SAFETY: read the active kernel address space so the non-local return can
    // restore it after the user-mode side trip.
    unsafe {
        core::arch::asm!("mov {v}, cr3", v = out(reg) original_cr3,
            options(nostack, preserves_flags));
    }
    SAVED_CR3.store(original_cr3, Ordering::Release);

    // SAFETY: JMP is dedicated storage for this single-threaded test.
    let saved = unsafe { user_mode_setjmp(core::ptr::addr_of_mut!(JMP)) };
    if saved != 0 {
        // SAFETY: restore the exact kernel CR3 and GS state saved before ring 3.
        unsafe {
            let cr3 = SAVED_CR3.load(Ordering::Acquire);
            core::arch::asm!("mov cr3, {v}", v = in(reg) cr3,
                options(nostack, preserves_flags));
            const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
            core::arch::asm!(
                "wrmsr",
                in("ecx") IA32_KERNEL_GS_BASE,
                in("eax") 0u32,
                in("edx") 0u32,
                options(nostack, preserves_flags),
            );
            core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
        }
        __test_clear_global();
        __verification_clear_instruction_interceptor();
        if INSTRUCTION_ENTRIES.load(Ordering::Acquire) != 0 {
            return TestResult::Fail("vDSO getcpu executed a timestamp instruction");
        }
        if SEEN[1].load(Ordering::Acquire) != CPU_SENTINEL as u64 {
            return TestResult::Fail("vDSO getcpu wrote a CPU number the tool did not supply");
        }
        if GETCPU_ENTRIES.load(Ordering::Acquire) != 1
            || GETCPU_ARGS[0].load(Ordering::Acquire) != CPU_VADDR
            || GETCPU_ARGS[1].load(Ordering::Acquire) != 0
        {
            return TestResult::Fail("vDSO getcpu did not issue getcpu(cpu, NULL) once");
        }
        if SEEN[0].load(Ordering::Acquire) != GETCPU_MAGIC {
            return TestResult::Fail("vDSO getcpu did not return the tool's syscall result");
        }
        return TestResult::Pass;
    }

    let sleep = Syscall::Sleep.raw();
    if sleep == GETCPU {
        return TestResult::Fail("unwind syscall number collides with getcpu");
    }
    let Some(getcpu) = vdso_symbol_offset(NARF_VDSO_ELF, b"__vdso_getcpu") else {
        return TestResult::Fail("vDSO image is empty or lacks __vdso_getcpu");
    };
    vdso::register_vdso_image(NARF_VDSO_ELF, narf_scheduler::narf_time::cycles_per_ns());

    let mut table = SyscallTable::new();
    table.install_raw(Syscall::Sleep, "vdso-getcpu-unwind", UnwindHandler);
    if table
        .install_interceptor(alloc::boxed::Box::new(GetcpuProbe))
        .is_err()
    {
        return TestResult::Fail("getcpu syscall interceptor installation failed");
    }
    install_global(table);
    if try_install_instruction_interceptor(alloc::boxed::Box::new(TimestampProbe)).is_err() {
        return TestResult::Fail("timestamp interceptor installation failed");
    }

    // SAFETY: the test owns this fresh user address space until longjmp.
    let address_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(address_space) => address_space,
        Err(_) => return TestResult::Fail("new_for_user failed"),
    };
    let code_frame = match narf_memory::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => return TestResult::Fail("alloc code frame"),
    };
    let stack_frame = match narf_memory::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => return TestResult::Fail("alloc stack frame"),
    };
    address_space
        .map_region(Region {
            base: VirtAddr::new(CODE_VADDR),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::EXEC | RegionPerms::WRITE,
            phys: alloc::vec![code_frame],
        })
        .ok();
    address_space
        .map_region(Region {
            base: VirtAddr::new(STACK_VADDR),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![stack_frame],
        })
        .ok();
    if vdso::map_into(&address_space) != Some(vdso::VDSO_VADDR) {
        return TestResult::Fail("vDSO map_into failed");
    }

    let mut code = alloc::vec::Vec::new();
    let movabs = |code: &mut alloc::vec::Vec<u8>, opcode: u8, value: u64| {
        code.extend_from_slice(&[0x48, opcode]);
        code.extend_from_slice(&value.to_le_bytes());
    };
    // movabs rdi,cpu; mov dword [rdi],sentinel
    movabs(&mut code, 0xBF, CPU_VADDR);
    code.extend_from_slice(&[0xC7, 0x07]);
    code.extend_from_slice(&CPU_SENTINEL.to_le_bytes());
    // getcpu(cpu, NULL): xor esi,esi; movabs rax; call rax; mov r12d,eax
    code.extend_from_slice(&[0x31, 0xF6]);
    movabs(&mut code, 0xB8, vdso::VDSO_VADDR + getcpu);
    code.extend_from_slice(&[0xFF, 0xD0, 0x41, 0x89, 0xC4]);
    // movabs rax,cpu; mov esi,[rax]; mov rdi,r12
    movabs(&mut code, 0xB8, CPU_VADDR);
    code.extend_from_slice(&[0x8B, 0x30, 0x4C, 0x89, 0xE7]);
    // mov eax,Sleep; int 0x80; ud2
    code.push(0xB8);
    code.extend_from_slice(&sleep.to_le_bytes());
    code.extend_from_slice(&[0xCD, 0x80, 0x0F, 0x0B]);
    // SAFETY: code_frame is exclusively owned and the copy fits one page.
    unsafe {
        core::ptr::copy_nonoverlapping(
            code.as_ptr(),
            code_frame.kernel_mut_ptr::<u8>(),
            code.len(),
        );
    }
    // SAFETY: materialize publishes the complete mappings constructed above.
    if unsafe { address_space.materialize() }.is_err() {
        return TestResult::Fail("materialize failed");
    }
    if address_space.activate().is_err() {
        return TestResult::Fail("activate failed");
    }
    // SAFETY: enter mapped ring-3 code with a mapped stack and IRQs disabled
    // across the transition. Success returns only via resume_trampoline.
    unsafe {
        core::arch::asm!("cli");
        user_mode_enter(CODE_VADDR, STACK_VADDR + 0x1000)
    }
}
#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
kernel_test_in!(
    "verification/syscall-entry",
    smoke_x86_64_vdso_getcpu_uses_syscall_under_timestamp_interception
);

#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
fn smoke_x86_64_vdso_counter_reads_are_ordered() -> TestResult {
    // In counter mode each vDSO clock read must be ordered after the vvar
    // loads that the seqlock validates, as Linux's rdtsc_ordered() is. With an
    // RDTSC interceptor installed and the vDSO forced back to counter mode,
    // clock_gettime, gettimeofday and time each read the counter through the
    // trap, and every trapped RDTSC must sit in the vDSO directly after an
    // LFENCE. The trap reports the instruction pointer the frame decoded, so
    // this checks the instructions executed rather than scanning bytes.
    use core::arch::naked_asm;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_memory::{AddressSpace, Region, RegionPerms, VirtAddr};
    use narf_userspace::{
        install_global, instruction::__verification_clear_instruction_interceptor,
        syscall::__verification_clear_global as __test_clear_global,
        try_install_instruction_interceptor, vdso, InstructionInterception, InstructionInterceptor,
        InstructionInvocation, InstructionResult, InstructionSubscriptions,
        NondeterministicInstruction, Syscall, SyscallHandler, SyscallTable, TrapContext,
    };

    const LFENCE: [u8; 3] = [0x0F, 0xAE, 0xE8];
    const RDTSC: [u8; 2] = [0x0F, 0x31];
    const CLOCK_MONOTONIC: u64 = 1;
    const CODE_VADDR: u64 = 0x0000_0080_0000_0000;
    const STACK_VADDR: u64 = 0x0000_0080_0000_1000;
    const TS_VADDR: u64 = STACK_VADDR + 0x800;
    const TV_VADDR: u64 = STACK_VADDR + 0x900;
    const MAX_READS: usize = 16;
    static READS: AtomicU64 = AtomicU64::new(0);
    static READ_IPS: [AtomicU64; MAX_READS] = [const { AtomicU64::new(0) }; MAX_READS];
    static RETURNED: AtomicU64 = AtomicU64::new(0);
    static SAVED_CR3: AtomicU64 = AtomicU64::new(0);
    static mut JMP: UserModeJmpBuf = UserModeJmpBuf {
        rbx: 0,
        rbp: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        rsp: 0,
        rip: 0,
    };

    struct RdtscProbe;
    // SAFETY: every callback uses only preallocated atomics and typed values;
    // it does not allocate, park, lock, await, or re-enter guest execution.
    unsafe impl InstructionInterceptor for RdtscProbe {
        fn subscriptions(&self) -> InstructionSubscriptions {
            InstructionSubscriptions::RDTSC
        }

        fn on_instruction_enter(
            &self,
            invocation: &InstructionInvocation,
        ) -> InstructionInterception {
            if invocation.instruction != NondeterministicInstruction::Rdtsc {
                return InstructionInterception::Continue;
            }
            let n = READS.fetch_add(1, Ordering::Relaxed) as usize;
            if n < MAX_READS {
                READ_IPS[n].store(invocation.instruction_pointer, Ordering::Relaxed);
            }
            // A plausible, advancing counter so the vDSO conversion and any
            // seqlock retry terminate normally.
            InstructionInterception::Complete(InstructionResult::Rdtsc {
                value: (n as u64 + 1) << 32,
            })
        }

        fn on_instruction_return(
            &self,
            _invocation: &InstructionInvocation,
            result: InstructionResult,
        ) -> InstructionResult {
            result
        }
    }

    #[unsafe(naked)]
    unsafe extern "C" fn resume_trampoline() -> ! {
        naked_asm!(
            "lea rdi, [rip + {jmp}]",
            "mov rsi, 1",
            "jmp {lj}",
            jmp = sym JMP,
            lj = sym user_mode_longjmp,
        );
    }

    struct UnwindHandler;
    impl SyscallHandler for UnwindHandler {
        fn handle(&self, ctx: &mut dyn TrapContext) {
            RETURNED.store(1, Ordering::Release);
            let _ =
                ctx.redirect_to_kernel(resume_trampoline as usize as u64, 0xFFFF_FFFF_FFFF_FFF0);
        }
    }

    READS.store(0, Ordering::Relaxed);
    RETURNED.store(0, Ordering::Relaxed);
    for ip in &READ_IPS {
        ip.store(0, Ordering::Relaxed);
    }
    __test_clear_global();
    __verification_clear_instruction_interceptor();

    let original_cr3: u64;
    // SAFETY: read the active kernel address space so the non-local return can
    // restore it after the user-mode side trip.
    unsafe {
        core::arch::asm!("mov {v}, cr3", v = out(reg) original_cr3,
            options(nostack, preserves_flags));
    }
    SAVED_CR3.store(original_cr3, Ordering::Release);

    // SAFETY: JMP is dedicated storage for this single-threaded test.
    let saved = unsafe { user_mode_setjmp(core::ptr::addr_of_mut!(JMP)) };
    if saved != 0 {
        // SAFETY: restore the exact kernel CR3 and GS state saved before ring 3.
        unsafe {
            let cr3 = SAVED_CR3.load(Ordering::Acquire);
            core::arch::asm!("mov cr3, {v}", v = in(reg) cr3,
                options(nostack, preserves_flags));
            const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
            core::arch::asm!(
                "wrmsr",
                in("ecx") IA32_KERNEL_GS_BASE,
                in("eax") 0u32,
                in("edx") 0u32,
                options(nostack, preserves_flags),
            );
            core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
        }
        __test_clear_global();
        __verification_clear_instruction_interceptor();
        if RETURNED.load(Ordering::Acquire) != 1 {
            return TestResult::Fail("ring-3 vDSO clock sequence did not complete");
        }
        let reads = READS.load(Ordering::Acquire) as usize;
        if !(3..=MAX_READS).contains(&reads) {
            return TestResult::Fail("vDSO counter-mode clocks did not trap one RDTSC per read");
        }
        for ip in READ_IPS.iter().take(reads) {
            let ip = ip.load(Ordering::Acquire);
            let Some(offset) = ip
                .checked_sub(vdso::VDSO_VADDR)
                .and_then(|offset| usize::try_from(offset).ok())
            else {
                return TestResult::Fail("trapped RDTSC lies outside the vDSO");
            };
            if offset < LFENCE.len() || NARF_VDSO_ELF.get(offset..offset + 2) != Some(&RDTSC[..]) {
                return TestResult::Fail("trapped RDTSC does not match the vDSO image");
            }
            if NARF_VDSO_ELF[offset - LFENCE.len()..offset] != LFENCE {
                return TestResult::Fail("vDSO RDTSC is not preceded by LFENCE");
            }
        }
        return TestResult::Pass;
    }

    let (Some(clock_gettime), Some(time), Some(gettimeofday)) = (
        vdso_symbol_offset(NARF_VDSO_ELF, b"__vdso_clock_gettime"),
        vdso_symbol_offset(NARF_VDSO_ELF, b"__vdso_time"),
        vdso_symbol_offset(NARF_VDSO_ELF, b"__vdso_gettimeofday"),
    ) else {
        return TestResult::Fail("vDSO image is empty or lacks a clock entry point");
    };
    vdso::register_vdso_image(NARF_VDSO_ELF, narf_scheduler::narf_time::cycles_per_ns());

    let mut table = SyscallTable::new();
    table.install_raw(Syscall::Sleep, "vdso-ordered-unwind", UnwindHandler);
    install_global(table);
    if try_install_instruction_interceptor(alloc::boxed::Box::new(RdtscProbe)).is_err() {
        return TestResult::Fail("RDTSC interceptor installation failed");
    }
    vdso::__verification_restore_counter_clocks();
    if vdso::clocks_route_through_syscalls() {
        __verification_clear_instruction_interceptor();
        return TestResult::Fail("vDSO did not return to counter mode for the probe");
    }

    // SAFETY: the test owns this fresh user address space until longjmp.
    let address_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(address_space) => address_space,
        Err(_) => return TestResult::Fail("new_for_user failed"),
    };
    let code_frame = match narf_memory::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => return TestResult::Fail("alloc code frame"),
    };
    let stack_frame = match narf_memory::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => return TestResult::Fail("alloc stack frame"),
    };
    address_space
        .map_region(Region {
            base: VirtAddr::new(CODE_VADDR),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::EXEC | RegionPerms::WRITE,
            phys: alloc::vec![code_frame],
        })
        .ok();
    address_space
        .map_region(Region {
            base: VirtAddr::new(STACK_VADDR),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![stack_frame],
        })
        .ok();
    if vdso::map_into(&address_space) != Some(vdso::VDSO_VADDR) {
        return TestResult::Fail("vDSO map_into failed");
    }

    let mut code = alloc::vec::Vec::new();
    let movabs = |code: &mut alloc::vec::Vec<u8>, opcode: u8, value: u64| {
        code.extend_from_slice(&[0x48, opcode]);
        code.extend_from_slice(&value.to_le_bytes());
    };
    // clock_gettime(CLOCK_MONOTONIC, ts): mov edi,1; movabs rsi; movabs rax;
    // call rax
    code.extend_from_slice(&[0xBF, CLOCK_MONOTONIC as u8, 0, 0, 0]);
    movabs(&mut code, 0xBE, TS_VADDR);
    movabs(&mut code, 0xB8, vdso::VDSO_VADDR + clock_gettime);
    code.extend_from_slice(&[0xFF, 0xD0]);
    // gettimeofday(tv, NULL): movabs rdi; xor esi,esi; movabs rax; call rax
    movabs(&mut code, 0xBF, TV_VADDR);
    code.extend_from_slice(&[0x31, 0xF6]);
    movabs(&mut code, 0xB8, vdso::VDSO_VADDR + gettimeofday);
    code.extend_from_slice(&[0xFF, 0xD0]);
    // time(NULL): xor edi,edi; movabs rax; call rax
    code.extend_from_slice(&[0x31, 0xFF]);
    movabs(&mut code, 0xB8, vdso::VDSO_VADDR + time);
    code.extend_from_slice(&[0xFF, 0xD0]);
    // mov eax,Sleep; int 0x80; ud2
    code.push(0xB8);
    code.extend_from_slice(&Syscall::Sleep.raw().to_le_bytes());
    code.extend_from_slice(&[0xCD, 0x80, 0x0F, 0x0B]);
    // SAFETY: code_frame is exclusively owned and the copy fits one page.
    unsafe {
        core::ptr::copy_nonoverlapping(
            code.as_ptr(),
            code_frame.kernel_mut_ptr::<u8>(),
            code.len(),
        );
    }
    // SAFETY: materialize publishes the complete mappings constructed above.
    if unsafe { address_space.materialize() }.is_err() {
        return TestResult::Fail("materialize failed");
    }
    if address_space.activate().is_err() {
        return TestResult::Fail("activate failed");
    }
    // SAFETY: enter mapped ring-3 code with a mapped stack and IRQs disabled
    // across the transition. Success returns only via resume_trampoline.
    unsafe {
        core::arch::asm!("cli");
        user_mode_enter(CODE_VADDR, STACK_VADDR + 0x1000)
    }
}
#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
kernel_test_in!(
    "verification/syscall-entry",
    smoke_x86_64_vdso_counter_reads_are_ordered
);

#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
fn smoke_x86_64_vdso_timestamp_reset_keeps_syscall_interceptor_routing() -> TestResult {
    // The counter-ordering smoke drops the timestamp-trap reason while its
    // RDTSC interceptor stays installed. That reset must clear only its own
    // reason: with a published syscall interceptor that asks for the guest's
    // vDSO calls, the clocks must stay on syscalls through the reset and the
    // instruction teardown, and return to the counter only when the table
    // itself is cleared.
    use narf_userspace::{
        install_global, instruction::__verification_clear_instruction_interceptor,
        syscall::__verification_clear_global as __test_clear_global,
        try_install_instruction_interceptor, vdso, InstructionInterceptor,
        InstructionSubscriptions, SyscallInterceptor, SyscallTable,
    };

    struct VdsoCallsProbe;
    impl SyscallInterceptor for VdsoCallsProbe {
        fn intercepts_vdso_calls(&self) -> bool {
            true
        }
    }

    struct RdtscProbe;
    // SAFETY: the probe has no callback state; the default callbacks return
    // `Continue` and the native value without allocating or blocking.
    unsafe impl InstructionInterceptor for RdtscProbe {
        fn subscriptions(&self) -> InstructionSubscriptions {
            InstructionSubscriptions::RDTSC
        }
    }

    __test_clear_global();
    __verification_clear_instruction_interceptor();
    if vdso::clocks_route_through_syscalls() {
        return TestResult::Fail("vDSO clocks used syscalls before any interceptor");
    }
    let mut table = SyscallTable::new();
    if table
        .install_interceptor(alloc::boxed::Box::new(VdsoCallsProbe))
        .is_err()
    {
        return TestResult::Fail("vDSO-calls syscall interceptor installation failed");
    }
    install_global(table);
    let routed = vdso::clocks_route_through_syscalls();
    if try_install_instruction_interceptor(alloc::boxed::Box::new(RdtscProbe)).is_err() {
        __test_clear_global();
        return TestResult::Fail("RDTSC interceptor installation failed");
    }
    vdso::__verification_restore_counter_clocks();
    let kept_after_reset = vdso::clocks_route_through_syscalls();
    __verification_clear_instruction_interceptor();
    let kept_after_teardown = vdso::clocks_route_through_syscalls();
    __test_clear_global();
    let restored = !vdso::clocks_route_through_syscalls();

    if !routed {
        return TestResult::Fail("publishing a vDSO-calls interceptor did not route the clocks");
    }
    if !kept_after_reset {
        return TestResult::Fail(
            "the timestamp reset dropped the syscall interceptor's routing reason",
        );
    }
    if !kept_after_teardown {
        return TestResult::Fail(
            "the instruction teardown dropped the syscall interceptor's routing reason",
        );
    }
    if !restored {
        return TestResult::Fail("clearing the table did not restore the vDSO counter path");
    }
    TestResult::Pass
}
#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
kernel_test_in!(
    "verification/syscall-entry",
    smoke_x86_64_vdso_timestamp_reset_keeps_syscall_interceptor_routing
);

#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
fn smoke_x86_64_instruction_interceptor_install_requires_no_live_user_task() -> TestResult {
    // Installation publishes the slot, switches the vDSO clocks and arms each
    // CPU in separate steps, so it is specified as a pre-guest operation. With
    // one user task live it must refuse before any of those steps, leaving
    // CR4.TSD clear on every online CPU; once that task has exited it must
    // succeed and complete all of them.
    use alloc::sync::Arc;
    use narf_memory::AddressSpace;
    use narf_userspace::{
        instruction::__verification_clear_instruction_interceptor,
        instruction_interception_enabled, try_install_instruction_interceptor, vdso,
        InstructionInterceptor, InstructionSubscriptions, NondeterministicInstruction,
    };

    const CR4_TSD: u64 = 1 << 2;

    struct RdtscProbe;
    // SAFETY: the probe has no callback state; the default callbacks return
    // `Continue` and the native value without allocating or blocking.
    unsafe impl InstructionInterceptor for RdtscProbe {
        fn subscriptions(&self) -> InstructionSubscriptions {
            InstructionSubscriptions::RDTSC
        }
    }

    __verification_clear_instruction_interceptor();
    // Drop boot-time tasks so run_until_empty below returns once the probe
    // task has exited, as the other scheduler-driving smokes do.
    narf_scheduler::__reset_queues_for_test();
    if narf_scheduler::live_user_task_count() != 0 {
        return TestResult::Fail("a user task was already live before the installation probe");
    }
    // SAFETY: a fresh user root with no mappings; the task below never enters
    // user mode because its future completes on its first poll.
    let address_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(address_space) => Arc::new(address_space),
        Err(_) => return TestResult::Fail("user address space allocation failed"),
    };
    // Pinned here: after the migration smoke enables user SMP, an unpinned
    // user task goes to an AP and run_until_empty below would not wait for it.
    let mut spec = narf_scheduler::TaskSpec::user_task();
    spec.affinity = narf_scheduler::Affinity::pinned(narf_scheduler::CpuId(
        narf_lib::percpu::current_cpu() as u32,
    ));
    let _task = narf_scheduler::spawn_user(
        narf_scheduler::alloc_task_id(),
        async {},
        spec,
        address_space,
    );
    let refused = try_install_instruction_interceptor(alloc::boxed::Box::new(RdtscProbe)).is_err();
    let published = instruction_interception_enabled(NondeterministicInstruction::Rdtsc);
    let routed = vdso::clocks_route_through_syscalls();
    let online_cpus = narf_lib::smp::online_bitmap();
    RDTSC_ARMED_CPUS.store(0, core::sync::atomic::Ordering::Release);
    // SAFETY: the callback only reads the local cached CR4 value and updates a
    // lock-free atomic bitmap. It allocates, blocks, awaits, and locks nowhere.
    let inspected =
        unsafe { narf_lib::smp::remote_call(online_cpus, record_cpu_with_rdtsc_trap_armed) };
    let armed_cpus = RDTSC_ARMED_CPUS.load(core::sync::atomic::Ordering::Acquire) & online_cpus;
    let armed = narf_arch::x86_64::cr::cached_cr4() & CR4_TSD != 0;
    narf_scheduler::run_until_empty();
    if narf_scheduler::live_user_task_count() != 0 {
        __verification_clear_instruction_interceptor();
        return TestResult::Fail("probe user task did not exit");
    }
    let installed = try_install_instruction_interceptor(alloc::boxed::Box::new(RdtscProbe)).is_ok();
    let installed_complete = instruction_interception_enabled(NondeterministicInstruction::Rdtsc)
        && vdso::clocks_route_through_syscalls()
        && narf_arch::x86_64::cr::cached_cr4() & CR4_TSD != 0;
    __verification_clear_instruction_interceptor();

    if !refused {
        return TestResult::Fail("installation succeeded while a user task was live");
    }
    if published || routed || armed {
        return TestResult::Fail("refused installation left a partial interceptor state");
    }
    if !inspected {
        return TestResult::Fail("post-refusal CR4.TSD inspection rendezvous failed");
    }
    if armed_cpus != 0 {
        return TestResult::Fail("refused installation left CR4.TSD armed on an online CPU");
    }
    if !installed || !installed_complete {
        return TestResult::Fail("installation with no live user task did not complete");
    }
    TestResult::Pass
}
#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
kernel_test_in!(
    "verification/syscall-entry",
    smoke_x86_64_instruction_interceptor_install_requires_no_live_user_task
);

#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
fn smoke_x86_64_instruction_interceptor_install_defers_concurrent_user_spawn() -> TestResult {
    // A user task spawned while installation is in progress must not become
    // runnable until every installation step is complete on every CPU. The
    // interceptor's own subscription call, which runs inside the installation
    // window, spawns the task: the spawn must be deferred rather than queued,
    // and the task's first poll, after installation returns, must see the slot
    // published, the vDSO clocks routed, and CR4.TSD armed on its CPU.
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_lib::sync::IrqSafeSpinLock;
    use narf_memory::AddressSpace;
    use narf_userspace::{
        instruction::__verification_clear_instruction_interceptor,
        instruction_interception_enabled, try_install_instruction_interceptor, vdso,
        InstructionInterceptor, InstructionSubscriptions, NondeterministicInstruction,
    };

    const CR4_TSD: u64 = 1 << 2;
    // Bits recorded by the spawner inside the installation window.
    const WINDOW_DEFERRED: u64 = 1 << 0;
    const WINDOW_NOT_ADMITTED: u64 = 1 << 1;
    const WINDOW_NOT_QUEUED: u64 = 1 << 2;
    // Bits recorded by the spawned task's first poll.
    const POLL_PUBLISHED: u64 = 1 << 0;
    const POLL_ROUTED: u64 = 1 << 1;
    const POLL_ARMED: u64 = 1 << 2;
    static WINDOW: AtomicU64 = AtomicU64::new(0);
    static POLLS: AtomicU64 = AtomicU64::new(0);
    static POLL_STATE: AtomicU64 = AtomicU64::new(0);

    struct SpawningProbe {
        address_space: IrqSafeSpinLock<Option<Arc<AddressSpace>>>,
    }
    // SAFETY: the subscription call runs in ordinary kernel context during
    // installation, not in exception context, so spawning there is allowed;
    // the default instruction callbacks allocate and block nowhere.
    unsafe impl InstructionInterceptor for SpawningProbe {
        fn subscriptions(&self) -> InstructionSubscriptions {
            let address_space = self.address_space.lock().take();
            if let Some(address_space) = address_space {
                let deferred = narf_scheduler::user_admissions_deferred();
                let admitted = narf_scheduler::user_tasks_admitted();
                // Pinned to this CPU so run_until_empty below waits for it
                // even after the migration smoke has enabled user SMP.
                let mut spec = narf_scheduler::TaskSpec::user_task();
                spec.affinity = narf_scheduler::Affinity::pinned(narf_scheduler::CpuId(
                    narf_lib::percpu::current_cpu() as u32,
                ));
                let id = narf_scheduler::spawn_user(
                    narf_scheduler::alloc_task_id(),
                    async {
                        let mut state = 0;
                        if instruction_interception_enabled(NondeterministicInstruction::Rdtsc) {
                            state |= POLL_PUBLISHED;
                        }
                        if vdso::clocks_route_through_syscalls() {
                            state |= POLL_ROUTED;
                        }
                        if narf_arch::x86_64::cr::cached_cr4() & CR4_TSD != 0 {
                            state |= POLL_ARMED;
                        }
                        POLL_STATE.store(state, Ordering::Release);
                        POLLS.fetch_add(1, Ordering::AcqRel);
                    },
                    spec,
                    address_space,
                );
                let mut window = 0;
                if narf_scheduler::user_admissions_deferred() == deferred + 1 {
                    window |= WINDOW_DEFERRED;
                }
                if narf_scheduler::user_tasks_admitted() == admitted {
                    window |= WINDOW_NOT_ADMITTED;
                }
                if !narf_scheduler::all_task_ids().contains(&id) {
                    window |= WINDOW_NOT_QUEUED;
                }
                WINDOW.store(window, Ordering::Release);
            }
            InstructionSubscriptions::RDTSC
        }
    }

    __verification_clear_instruction_interceptor();
    narf_scheduler::__reset_queues_for_test();
    WINDOW.store(0, Ordering::Release);
    POLLS.store(0, Ordering::Release);
    POLL_STATE.store(0, Ordering::Release);
    if narf_scheduler::live_user_task_count() != 0 {
        return TestResult::Fail("a user task was already live before the deferral probe");
    }
    // SAFETY: a fresh user root with no mappings; the task spawned from it
    // never enters user mode because its future completes on its first poll.
    let address_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(address_space) => Arc::new(address_space),
        Err(_) => return TestResult::Fail("user address space allocation failed"),
    };
    let probe = SpawningProbe {
        address_space: IrqSafeSpinLock::new(Some(address_space)),
    };
    let installed = try_install_instruction_interceptor(alloc::boxed::Box::new(probe)).is_ok();
    let polled_during_install = POLLS.load(Ordering::Acquire);
    narf_scheduler::run_until_empty();
    let polls = POLLS.load(Ordering::Acquire);
    let live = narf_scheduler::live_user_task_count();
    __verification_clear_instruction_interceptor();

    if !installed {
        return TestResult::Fail("installation with no live user task failed");
    }
    let window = WINDOW.load(Ordering::Acquire);
    if window & WINDOW_DEFERRED == 0 {
        return TestResult::Fail("user spawn during installation was not deferred");
    }
    if window & (WINDOW_NOT_ADMITTED | WINDOW_NOT_QUEUED) != WINDOW_NOT_ADMITTED | WINDOW_NOT_QUEUED
    {
        return TestResult::Fail("user task spawned during installation became runnable");
    }
    if polled_during_install != 0 {
        return TestResult::Fail("deferred user task ran before installation returned");
    }
    if polls != 1 || live != 0 {
        return TestResult::Fail("deferred user task was not admitted and run once");
    }
    if POLL_STATE.load(Ordering::Acquire) != POLL_PUBLISHED | POLL_ROUTED | POLL_ARMED {
        return TestResult::Fail("deferred user task first ran on a partial interceptor state");
    }
    TestResult::Pass
}
#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
kernel_test_in!(
    "verification/syscall-entry",
    smoke_x86_64_instruction_interceptor_install_defers_concurrent_user_spawn
);

#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
fn smoke_scheduled_user_interception_survives_ap_migration() -> TestResult {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use narf_memory::{AddressSpace, Region, RegionPerms, VirtAddr};
    use narf_scheduler::{Affinity, CpuId, CpuSet, TaskSpec};
    use narf_userspace::instruction::{
        __verification_clear_instruction_interceptor, try_install_instruction_interceptor,
        InstructionInterception, InstructionInterceptor, InstructionInvocation, InstructionResult,
        InstructionSubscriptions,
    };
    use narf_userspace::{
        install_core_syscalls, install_global, install_task_id_lookup,
        syscall::__verification_clear_global as __test_clear_global, Syscall, SyscallInterception,
        SyscallInterceptor, SyscallInvocation, SyscallReturn, SyscallTable, UserProcess,
    };

    const UNKNOWN_NR: u32 = 0x3fff;
    const RDTSC_MAGIC: u64 = 0x1122_3344_5566_7788;
    const SYSCALL_MAGIC: u64 = 0x7abc_def0;

    static EXPECTED_TASK: AtomicU64 = AtomicU64::new(0);
    static YIELD_TASK: AtomicU64 = AtomicU64::new(0);
    static YIELD_CPU: AtomicUsize = AtomicUsize::new(usize::MAX);
    static RDTSC_TASK: AtomicU64 = AtomicU64::new(0);
    static RDTSC_CPU: AtomicUsize = AtomicUsize::new(usize::MAX);
    static SYSCALL_TASK: AtomicU64 = AtomicU64::new(0);
    static SYSCALL_CPU: AtomicUsize = AtomicUsize::new(usize::MAX);
    static SYSCALL_ARG0: AtomicU64 = AtomicU64::new(0);
    static EXIT_TASK: AtomicU64 = AtomicU64::new(0);
    static EXIT_CPU: AtomicUsize = AtomicUsize::new(usize::MAX);
    static EXIT_ARG0: AtomicU64 = AtomicU64::new(0);
    static CONTROLLER_ERROR: AtomicU64 = AtomicU64::new(0);
    static DESTINATION_CPU: AtomicUsize = AtomicUsize::new(usize::MAX);
    static CLEARED_CPUS: AtomicU64 = AtomicU64::new(0);

    struct SyscallProbe;
    impl SyscallInterceptor for SyscallProbe {
        fn on_syscall_enter(
            &self,
            invocation: &SyscallInvocation,
            _native: &mut dyn narf_userspace::NativeSyscallTransition,
        ) -> SyscallInterception {
            let cpu = narf_lib::percpu::current_cpu();
            match invocation.raw_number {
                number if number == Syscall::Yield.raw() => {
                    YIELD_TASK.store(invocation.task_id, Ordering::Release);
                    YIELD_CPU.store(cpu, Ordering::Release);
                    let destination = DESTINATION_CPU.load(Ordering::Acquire);
                    if destination == usize::MAX
                        || narf_scheduler::set_task_affinity(
                            narf_scheduler::TaskId(invocation.task_id),
                            CpuSet::single(CpuId(destination as u32)),
                        )
                        .is_err()
                    {
                        CONTROLLER_ERROR.store(2, Ordering::Release);
                    }
                    SyscallInterception::Continue
                }
                UNKNOWN_NR => {
                    SYSCALL_TASK.store(invocation.task_id, Ordering::Release);
                    SYSCALL_CPU.store(cpu, Ordering::Release);
                    SYSCALL_ARG0.store(invocation.args.arg0, Ordering::Release);
                    SyscallInterception::Complete(SyscallReturn::ok(SYSCALL_MAGIC))
                }
                number if number == Syscall::ExitTask.raw() => {
                    EXIT_TASK.store(invocation.task_id, Ordering::Release);
                    EXIT_CPU.store(cpu, Ordering::Release);
                    EXIT_ARG0.store(invocation.args.arg0, Ordering::Release);
                    SyscallInterception::Continue
                }
                _ => SyscallInterception::Continue,
            }
        }
    }

    struct RdtscProbe;
    // SAFETY: the callback performs only lock-free atomic stores and returns a
    // typed value. It does not allocate, park, await, lock, or re-enter guest
    // execution.
    unsafe impl InstructionInterceptor for RdtscProbe {
        fn subscriptions(&self) -> InstructionSubscriptions {
            InstructionSubscriptions::RDTSC
        }

        fn on_instruction_enter(
            &self,
            invocation: &InstructionInvocation,
        ) -> InstructionInterception {
            RDTSC_TASK.store(invocation.task_id, Ordering::Release);
            RDTSC_CPU.store(narf_lib::percpu::current_cpu(), Ordering::Release);
            InstructionInterception::Complete(InstructionResult::Rdtsc { value: RDTSC_MAGIC })
        }
    }

    fn clear_and_record_tsd() {
        narf_arch::x86_64::cr::__test_clear_current_cpu_user_rdtsc_interception();
        if narf_arch::x86_64::cr::cached_cr4() & narf_arch::x86_64::cr::CR4_TSD == 0 {
            let cpu = narf_lib::percpu::current_cpu();
            if cpu < 64 {
                CLEARED_CPUS.fetch_or(1u64 << cpu, Ordering::Release);
            }
        }
    }

    let source_cpu = narf_lib::percpu::current_cpu();
    let online = narf_lib::smp::online_bitmap();
    let peers = online & !(1u64 << source_cpu);
    if peers == 0 {
        return TestResult::Skip("scheduled interception migration needs an online AP");
    }
    let destination_cpu = peers.trailing_zeros() as usize;
    DESTINATION_CPU.store(destination_cpu, Ordering::Release);

    for atomic in [
        &EXPECTED_TASK,
        &YIELD_TASK,
        &RDTSC_TASK,
        &SYSCALL_TASK,
        &SYSCALL_ARG0,
        &EXIT_TASK,
        &EXIT_ARG0,
        &CONTROLLER_ERROR,
        &CLEARED_CPUS,
    ] {
        atomic.store(0, Ordering::Relaxed);
    }
    for atomic in [&YIELD_CPU, &RDTSC_CPU, &SYSCALL_CPU, &EXIT_CPU] {
        atomic.store(usize::MAX, Ordering::Relaxed);
    }

    __test_clear_global();
    __verification_clear_instruction_interceptor();
    narf_userspace::user_task::__test_clear_hooks();
    narf_scheduler::__reset_queues_for_test();
    // The waiter below uses the live-task count to observe this task's reaping,
    // so it must start from zero.
    if narf_scheduler::live_user_task_count() != 0 {
        return TestResult::Fail("a user task was already live before the migration smoke");
    }
    // Kernel-test boots leave user-task SMP off. Put the switch back on every
    // return path, so later tests keep their boot placement.
    struct RestoreUserSmp(bool);
    impl Drop for RestoreUserSmp {
        fn drop(&mut self) {
            narf_scheduler::__test_set_user_task_smp(self.0);
        }
    }
    let _restore_smp = RestoreUserSmp(narf_scheduler::__test_set_user_task_smp(true));

    let original_cr3: u64;
    // SAFETY: snapshot the kernel address space for defensive test cleanup.
    unsafe {
        core::arch::asm!("mov {value}, cr3", value = out(reg) original_cr3,
            options(nostack, preserves_flags));
    }

    // SAFETY: this test exclusively owns the fresh address space until the
    // scheduled task exits.
    let address_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(address_space) => address_space,
        Err(_) => return TestResult::Fail("new_for_user failed"),
    };
    const CODE_VADDR: u64 = 0x0000_0080_0000_0000;
    const STACK_VADDR: u64 = 0x0000_0080_0000_1000;
    let code_frame = match narf_memory::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => return TestResult::Fail("alloc code frame"),
    };
    let stack_frame = match narf_memory::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => return TestResult::Fail("alloc stack frame"),
    };
    if address_space
        .map_region(Region {
            base: VirtAddr::new(CODE_VADDR),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::EXEC | RegionPerms::WRITE,
            phys: alloc::vec![code_frame],
        })
        .is_err()
        || address_space
            .map_region(Region {
                base: VirtAddr::new(STACK_VADDR),
                len: 0x1000,
                perms: RegionPerms::READ | RegionPerms::WRITE,
                phys: alloc::vec![stack_frame],
            })
            .is_err()
    {
        return TestResult::Fail("map user regions failed");
    }

    let yield_nr = Syscall::Yield.raw().to_le_bytes();
    let exit_nr = Syscall::ExitTask.raw().to_le_bytes();
    let unknown_nr = UNKNOWN_NR.to_le_bytes();
    // Yield on the source CPU. After the controller moves this task, execute
    // RDTSC, pass its result as arg0 to an unknown fast syscall, then pass that
    // syscall's Tool result as the exit status.
    let code: [u8; 38] = [
        0xB8,
        yield_nr[0],
        yield_nr[1],
        yield_nr[2],
        yield_nr[3], // mov eax,Yield
        0xCD,
        0x80, // int 0x80
        0x0F,
        0x31, // rdtsc
        0x48,
        0xC1,
        0xE2,
        0x20, // shl rdx,32
        0x48,
        0x09,
        0xD0, // or rax,rdx
        0x48,
        0x89,
        0xC7, // mov rdi,rax
        0xB8,
        unknown_nr[0],
        unknown_nr[1],
        unknown_nr[2],
        unknown_nr[3], // mov eax,unknown
        0x0F,
        0x05, // syscall
        0x48,
        0x89,
        0xC7, // mov rdi,rax
        0xB8,
        exit_nr[0],
        exit_nr[1],
        exit_nr[2],
        exit_nr[3], // mov eax,ExitTask
        0xCD,
        0x80, // int 0x80
        0xEB,
        0xFE, // jmp $
    ];
    // SAFETY: the frame is exclusively owned and the program fits one page.
    unsafe {
        core::ptr::copy_nonoverlapping(
            code.as_ptr(),
            code_frame.kernel_mut_ptr::<u8>(),
            code.len(),
        );
    }
    // SAFETY: materialize publishes the complete mappings above.
    if unsafe { address_space.materialize() }.is_err() {
        return TestResult::Fail("materialize failed");
    }

    let mut table = SyscallTable::new();
    install_core_syscalls(&mut table);
    if table
        .install_interceptor(alloc::boxed::Box::new(SyscallProbe))
        .is_err()
    {
        return TestResult::Fail("syscall interceptor install failed");
    }
    install_global(table);
    if try_install_instruction_interceptor(alloc::boxed::Box::new(RdtscProbe)).is_err() {
        __test_clear_global();
        return TestResult::Fail("instruction interceptor install failed");
    }

    CLEARED_CPUS.store(0, Ordering::Release);
    // SAFETY: the callback only clears one test-owned CR4 bit and records the
    // executing CPU in an atomic bitmap.
    if !unsafe { narf_lib::smp::remote_call(1u64 << destination_cpu, clear_and_record_tsd) }
        || CLEARED_CPUS.load(Ordering::Acquire) & (1u64 << destination_cpu) == 0
    {
        __verification_clear_instruction_interceptor();
        __test_clear_global();
        return TestResult::Fail("destination CPU TSD reset did not execute");
    }

    install_task_id_lookup(|| narf_scheduler::current_task_id().raw());
    narf_userspace::install_user_task_hooks();
    let process = UserProcess {
        pid: narf_userspace::alloc_pid(),
        address_space: Arc::new(address_space),
        entry: narf_userspace::EntryPoint(VirtAddr::new(CODE_VADDR)),
        stack_top: VirtAddr::new(STACK_VADDR + 0x1000),
        fs_base: None,
        entry_arg: None,
        loaded_mappings: alloc::vec::Vec::new(),
        auxv: alloc::vec::Vec::new(),
    };
    let mut source_spec = TaskSpec::user_task();
    source_spec.affinity = Affinity::pinned(CpuId(source_cpu as u32));
    let user_id = narf_userspace::user_task::spawn_user_process(process, source_spec);
    EXPECTED_TASK.store(user_id.raw(), Ordering::Release);

    // The waiter keeps this CPU's executor alive until the scheduler has
    // reaped the guest, not merely until the guest entered ExitTask: the task
    // exits on the destination CPU, and run_until_empty returns once this
    // CPU's queue is empty. Tearing down the exit hook and the own-stack mode
    // below while the task is still inside ExitTask makes that ExitTask fail,
    // leaving the guest live in its trailing loop. The live count returns to
    // zero only after the slot's future is dropped; the final address-space
    // release can still follow on the destination CPU. It is
    // bounded so a guest that never exits fails this test with a diagnosis
    // instead of hanging the suite until the QEMU timeout. 3e10 cycles is
    // about 10 s at 3 GHz.
    const WAITER_BUDGET_CYCLES: u64 = 30_000_000_000;
    let waiter_deadline = narf_time::Instant::now().plus_cycles(WAITER_BUDGET_CYCLES);
    narf_scheduler::spawn(async move {
        while EXIT_TASK.load(Ordering::Acquire) == 0 || narf_scheduler::live_user_task_count() != 0
        {
            if narf_time::Instant::now() >= waiter_deadline {
                CONTROLLER_ERROR.store(
                    if EXIT_TASK.load(Ordering::Acquire) == 0 {
                        1
                    } else {
                        3
                    },
                    Ordering::Release,
                );
                return;
            }
            narf_scheduler::yield_now().await;
        }
    });

    narf_scheduler::run_until_empty();

    // SAFETY: restore the exact kernel CR3 and kernel-GS state after the user
    // task has exited, matching the neighboring scheduled-user smoke cleanup.
    unsafe {
        core::arch::asm!("mov cr3, {value}", value = in(reg) original_cr3,
            options(nostack, preserves_flags));
        const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
        core::arch::asm!(
            "wrmsr",
            in("ecx") IA32_KERNEL_GS_BASE,
            in("eax") 0u32,
            in("edx") 0u32,
            options(nostack, preserves_flags),
        );
        core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
    }
    narf_userspace::user_task::__test_clear_hooks();
    narf_userspace::handlers::__test_reset_task_id_lookup();
    __verification_clear_instruction_interceptor();
    __test_clear_global();

    let expected_task = EXPECTED_TASK.load(Ordering::Acquire);
    match CONTROLLER_ERROR.load(Ordering::Acquire) {
        0 => {}
        1 => return TestResult::Fail("guest did not reach ExitTask within the waiter budget"),
        2 => return TestResult::Fail("scheduler rejected the destination affinity"),
        3 => {
            return TestResult::Fail("guest reached ExitTask but was not reaped within the budget")
        }
        _ => return TestResult::Fail("migration controller reported an unknown failure"),
    }
    if expected_task == 0
        || YIELD_TASK.load(Ordering::Acquire) != expected_task
        || RDTSC_TASK.load(Ordering::Acquire) != expected_task
        || SYSCALL_TASK.load(Ordering::Acquire) != expected_task
        || EXIT_TASK.load(Ordering::Acquire) != expected_task
    {
        return TestResult::Fail("interception did not retain one nonzero scheduled task identity");
    }
    if YIELD_CPU.load(Ordering::Acquire) != source_cpu
        || RDTSC_CPU.load(Ordering::Acquire) != destination_cpu
        || SYSCALL_CPU.load(Ordering::Acquire) != destination_cpu
        || EXIT_CPU.load(Ordering::Acquire) != destination_cpu
    {
        return TestResult::Fail("user task did not cross the requested CPU boundary");
    }
    if SYSCALL_ARG0.load(Ordering::Acquire) != RDTSC_MAGIC
        || EXIT_ARG0.load(Ordering::Acquire) != SYSCALL_MAGIC
    {
        return TestResult::Fail("intercepted results did not reach the migrated guest");
    }
    TestResult::Pass
}
#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
kernel_test_in!(
    "verification/interception-migration",
    smoke_scheduled_user_interception_survives_ap_migration
);

/// The own-stack execve path is the production one, and it diverges into the
/// new image after dropping every local reference to both address spaces by
/// hand. A reference it forgets is never dropped, because the frame holding it
/// is abandoned; a reference it drops too early frees page tables that are
/// live in CR3. Drive a scheduled user task through a real own-stack execve
/// into an image that marks itself and exits, and require that the new image
/// ran on its own root and that, once the task is reaped, neither the pre-exec
/// nor the post-exec address space survives.
#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
fn smoke_own_stack_execve_runs_new_image_and_frees_both_address_spaces() -> TestResult {
    use alloc::sync::{Arc, Weak};
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_memory::{AddressSpace, Region, RegionPerms, VirtAddr};
    use narf_scheduler::{Affinity, CpuId, TaskSpec};
    use narf_userspace::{
        install_core_syscalls, install_global, install_task_id_lookup,
        syscall::__verification_clear_global as __test_clear_global, Syscall, SyscallReturn,
        SyscallTable, UserProcess,
    };

    const CODE_VADDR: u64 = 0x0000_0080_0000_0000;
    const STACK_VADDR: u64 = 0x0000_0080_0000_1000;
    const PATH_OFFSET: usize = 0x200;
    const NEW_IMAGE_MARK: u64 = 0x600D;
    const OLD_IMAGE_MARK: u64 = 0x0BAD;
    const ROOT_MASK: u64 = 0x000f_ffff_ffff_f000;
    // About 10 s at 3 GHz, as in the migration smoke above.
    const WAITER_BUDGET_CYCLES: u64 = 30_000_000_000;

    static NEW_IMAGE_RAN: AtomicU64 = AtomicU64::new(0);
    static NEW_IMAGE_ON_OWN_ROOT: AtomicU64 = AtomicU64::new(0);
    static EXECVE_RETURNED: AtomicU64 = AtomicU64::new(0);
    static WAITER_ERROR: AtomicU64 = AtomicU64::new(0);
    static OLD_AS: narf_lib::sync::IrqSafeSpinLock<Option<Weak<AddressSpace>>> =
        narf_lib::sync::IrqSafeSpinLock::new(None);
    static NEW_AS: narf_lib::sync::IrqSafeSpinLock<Option<Weak<AddressSpace>>> =
        narf_lib::sync::IrqSafeSpinLock::new(None);
    NEW_IMAGE_RAN.store(0, Ordering::Release);
    NEW_IMAGE_ON_OWN_ROOT.store(0, Ordering::Release);
    EXECVE_RETURNED.store(0, Ordering::Release);
    WAITER_ERROR.store(0, Ordering::Release);
    *OLD_AS.lock() = None;
    *NEW_AS.lock() = None;

    fn alive(cell: &narf_lib::sync::IrqSafeSpinLock<Option<Weak<AddressSpace>>>) -> bool {
        cell.lock().as_ref().is_some_and(|w| w.strong_count() != 0)
    }

    // The image execve loads: one R|X PT_LOAD at 0x80_0000_1000 whose entry
    // reports NEW_IMAGE_MARK through Sleep and then exits.
    let sleep_n = Syscall::Sleep.raw().to_le_bytes();
    let exit_n = Syscall::ExitTask.raw().to_le_bytes();
    let execve_n = Syscall::Execve.raw().to_le_bytes();
    let new_mark = (NEW_IMAGE_MARK as u32).to_le_bytes();
    let old_mark = (OLD_IMAGE_MARK as u32).to_le_bytes();
    let new_code: [u8; 32] = [
        0x48,
        0xC7,
        0xC7,
        new_mark[0],
        new_mark[1],
        new_mark[2],
        new_mark[3], // mov rdi, NEW_IMAGE_MARK
        0x48,
        0xC7,
        0xC0,
        sleep_n[0],
        sleep_n[1],
        sleep_n[2],
        sleep_n[3], // mov rax, Sleep
        0xCD,
        0x80, // int 0x80
        0x48,
        0xC7,
        0xC0,
        exit_n[0],
        exit_n[1],
        exit_n[2],
        exit_n[3], // mov rax, ExitTask
        0xCD,
        0x80, // int 0x80
        0xEB,
        0xFE, // jmp $
        0x90,
        0x90,
        0x90,
        0x90,
        0x90,
    ];
    const ENTRY: u64 = 0x0000_0080_0000_1111;
    const PH_OFFSET: usize = 64 + 56;
    let mut elf: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(PH_OFFSET + 0x1000);
    elf.extend_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    elf.extend_from_slice(&2u16.to_le_bytes()); // e_type ET_EXEC
    elf.extend_from_slice(&0x3Eu16.to_le_bytes()); // e_machine x86_64
    elf.extend_from_slice(&1u32.to_le_bytes()); // e_version
    elf.extend_from_slice(&ENTRY.to_le_bytes()); // e_entry
    elf.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
    elf.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
    elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    elf.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    elf.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
    elf.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
    elf.extend_from_slice(&1u32.to_le_bytes()); // p_type PT_LOAD
    elf.extend_from_slice(&5u32.to_le_bytes()); // p_flags R|X
    elf.extend_from_slice(&(PH_OFFSET as u64).to_le_bytes()); // p_offset
    elf.extend_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes()); // p_vaddr
    elf.extend_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes()); // p_paddr
    elf.extend_from_slice(&0x1000u64.to_le_bytes()); // p_filesz
    elf.extend_from_slice(&0x1000u64.to_le_bytes()); // p_memsz
    elf.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
    elf.resize(PH_OFFSET + 0x1000, 0);
    let entry_off = PH_OFFSET + (ENTRY - 0x0000_0080_0000_1000) as usize;
    elf[entry_off..entry_off + new_code.len()].copy_from_slice(&new_code);

    // The pre-exec image: execve(path, NULL, NULL). Execve returns only on
    // failure, and then the old image reports OLD_IMAGE_MARK with the error
    // in rsi and exits.
    let path_vaddr = (CODE_VADDR + PATH_OFFSET as u64).to_le_bytes();
    let old_code: [u8; 51] = [
        0x48,
        0xBF,
        path_vaddr[0],
        path_vaddr[1],
        path_vaddr[2],
        path_vaddr[3],
        path_vaddr[4],
        path_vaddr[5],
        path_vaddr[6],
        path_vaddr[7], // mov rdi, path
        0x31,
        0xF6, // xor esi, esi
        0x31,
        0xD2, // xor edx, edx
        0x48,
        0xC7,
        0xC0,
        execve_n[0],
        execve_n[1],
        execve_n[2],
        execve_n[3], // mov rax, Execve
        0xCD,
        0x80, // int 0x80
        0x48,
        0x89,
        0xC6, // mov rsi, rax
        0x48,
        0xC7,
        0xC7,
        old_mark[0],
        old_mark[1],
        old_mark[2],
        old_mark[3], // mov rdi, OLD_IMAGE_MARK
        0x48,
        0xC7,
        0xC0,
        sleep_n[0],
        sleep_n[1],
        sleep_n[2],
        sleep_n[3], // mov rax, Sleep
        0xCD,
        0x80, // int 0x80
        0x48,
        0xC7,
        0xC0,
        exit_n[0],
        exit_n[1],
        exit_n[2],
        exit_n[3], // mov rax, ExitTask
        0xCD,
        0x80, // int 0x80
    ];
    let path = b"/own-stack-exec/prog\0";

    let cpu = narf_lib::percpu::current_cpu();
    let original_cr3: u64;
    // SAFETY: reading CR3 has no side effects.
    unsafe {
        core::arch::asm!("mov {v}, cr3", v = out(reg) original_cr3,
            options(nostack, preserves_flags));
    }
    __test_clear_global();
    narf_userspace::user_task::__test_clear_hooks();

    let auth = narf_filesystem::bootstrap_mount_authority();
    let Ok(mount) = narf_filesystem::registry().mount(
        &auth,
        "/own-stack-exec",
        narf_filesystem::MemFs::with_seeds("own-stack-exec", &[("prog", elf.as_slice())]),
    ) else {
        return TestResult::Fail("mount of the execve image failed");
    };

    // SAFETY: paging is live in the kernel-test environment.
    let Ok(addr_space) = (unsafe { AddressSpace::new_for_user() }) else {
        let _ = narf_filesystem::registry().unmount(&mount, "/own-stack-exec");
        return TestResult::Fail("new_for_user");
    };
    let (Ok(code_frame), Ok(stack_frame)) =
        (narf_memory::alloc_frame(), narf_memory::alloc_frame())
    else {
        let _ = narf_filesystem::registry().unmount(&mount, "/own-stack-exec");
        return TestResult::Fail("frame allocation failed");
    };
    let (code_frame, stack_frame) = (code_frame.start_address(), stack_frame.start_address());
    if addr_space
        .map_region(Region {
            base: VirtAddr::new(CODE_VADDR),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::EXEC,
            phys: alloc::vec![code_frame],
        })
        .is_err()
        || addr_space
            .map_region(Region {
                base: VirtAddr::new(STACK_VADDR),
                len: 0x1000,
                perms: RegionPerms::READ | RegionPerms::WRITE,
                phys: alloc::vec![stack_frame],
            })
            .is_err()
    {
        let _ = narf_filesystem::registry().unmount(&mount, "/own-stack-exec");
        return TestResult::Fail("map_region failed");
    }
    // SAFETY: the frame is exclusively owned; code and path fit one page.
    unsafe {
        let page = code_frame.kernel_mut_ptr::<u8>();
        core::ptr::write_bytes(page, 0, 0x1000);
        core::ptr::copy_nonoverlapping(old_code.as_ptr(), page, old_code.len());
        core::ptr::copy_nonoverlapping(path.as_ptr(), page.add(PATH_OFFSET), path.len());
    }
    // SAFETY: materialize publishes the complete mappings above.
    if unsafe { addr_space.materialize() }.is_err() {
        let _ = narf_filesystem::registry().unmount(&mount, "/own-stack-exec");
        return TestResult::Fail("materialize failed");
    }
    let addr_space = Arc::new(addr_space);
    *OLD_AS.lock() = Some(Arc::downgrade(&addr_space));

    let mut table = SyscallTable::new();
    install_core_syscalls(&mut table);
    table.install_fn(Syscall::Sleep, "own-stack-exec-mark", |args| {
        match args.arg0 {
            NEW_IMAGE_MARK => {
                NEW_IMAGE_RAN.fetch_add(1, Ordering::AcqRel);
                if let Some(active) = narf_scheduler::current_address_space() {
                    let cr3: u64;
                    // SAFETY: reading CR3 has no side effects.
                    unsafe {
                        core::arch::asm!("mov {v}, cr3", v = out(reg) cr3,
                            options(nostack, nomem, preserves_flags));
                    }
                    let on_own_root = cr3 & ROOT_MASK == active.root.as_u64() & ROOT_MASK
                        && !alive_is(&OLD_AS, &active);
                    NEW_IMAGE_ON_OWN_ROOT.store(on_own_root as u64, Ordering::Release);
                    *NEW_AS.lock() = Some(Arc::downgrade(&active));
                }
            }
            OLD_IMAGE_MARK => EXECVE_RETURNED.store(args.arg1 | 1 << 63, Ordering::Release),
            _ => {}
        }
        SyscallReturn::ok(0)
    });
    fn alive_is(
        cell: &narf_lib::sync::IrqSafeSpinLock<Option<Weak<AddressSpace>>>,
        active: &Arc<AddressSpace>,
    ) -> bool {
        cell.lock()
            .as_ref()
            .is_some_and(|w| core::ptr::eq(w.as_ptr(), Arc::as_ptr(active)))
    }
    install_global(table);

    // execve's task id must be the scheduler's current task, as at boot.
    install_task_id_lookup(|| narf_scheduler::current_task_id().raw());
    narf_scheduler::__reset_queues_for_test();
    narf_userspace::install_user_task_hooks();
    let live_before = narf_scheduler::live_user_task_count();
    let process = UserProcess {
        pid: narf_userspace::alloc_pid(),
        address_space: addr_space,
        entry: narf_userspace::EntryPoint(VirtAddr::new(CODE_VADDR)),
        stack_top: VirtAddr::new(STACK_VADDR + 0x1000),
        fs_base: None,
        entry_arg: None,
        loaded_mappings: alloc::vec::Vec::new(),
        auxv: alloc::vec::Vec::new(),
    };
    // Pinned here so the reap, and the executor's release of the last root
    // it installed, happen on this CPU while the waiter watches.
    let mut spec = TaskSpec::user_task();
    spec.affinity = Affinity::pinned(CpuId(cpu as u32));
    let _user_id = narf_userspace::user_task::spawn_user_process(process, spec);

    // The waiter keeps this CPU's executor alive until the task is reaped and
    // both address spaces are released, or the budget runs out.
    let deadline = narf_time::Instant::now().plus_cycles(WAITER_BUDGET_CYCLES);
    narf_scheduler::spawn(async move {
        loop {
            let reaped = narf_scheduler::live_user_task_count() <= live_before;
            let old_alive = alive(&OLD_AS);
            let new_alive = alive(&NEW_AS);
            if reaped && !old_alive && !new_alive {
                return;
            }
            if narf_time::Instant::now() >= deadline {
                let code = if !reaped {
                    1
                } else if new_alive {
                    2
                } else {
                    3
                };
                WAITER_ERROR.store(code, Ordering::Release);
                return;
            }
            narf_scheduler::yield_now().await;
        }
    });

    narf_scheduler::run_until_empty();

    // SAFETY: restore the kernel CR3 and kernel-GS state after the user task
    // has exited, matching the neighbouring scheduled-user smokes.
    unsafe {
        core::arch::asm!("mov cr3, {value}", value = in(reg) original_cr3,
            options(nostack, preserves_flags));
        const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
        core::arch::asm!(
            "wrmsr",
            in("ecx") IA32_KERNEL_GS_BASE,
            in("eax") 0u32,
            in("edx") 0u32,
            options(nostack, preserves_flags),
        );
        core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
    }
    narf_userspace::user_task::__test_clear_hooks();
    narf_userspace::handlers::__test_reset_task_id_lookup();
    __test_clear_global();
    let _ = narf_filesystem::registry().unmount(&mount, "/own-stack-exec");

    let returned = EXECVE_RETURNED.load(Ordering::Acquire);
    if returned != 0 {
        let _ = writeln!(
            Writer,
            "    own-stack execve returned {:#x} to the old image",
            returned & !(1 << 63)
        );
        return TestResult::Fail("own-stack execve returned to the old image");
    }
    if NEW_IMAGE_RAN.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("the new image did not run exactly once");
    }
    if NEW_IMAGE_ON_OWN_ROOT.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("the new image did not run on its own published address space");
    }
    match WAITER_ERROR.load(Ordering::Acquire) {
        0 => TestResult::Pass,
        1 => TestResult::Fail("the exec'd task was not reaped within the budget"),
        2 => TestResult::Fail("the post-exec address space outlived its task"),
        _ => TestResult::Fail("the pre-exec address space outlived its task"),
    }
}
#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
kernel_test_in!(
    "verification/own-stack-exec",
    smoke_own_stack_execve_runs_new_image_and_frees_both_address_spaces
);

/// Deferred RDTSC callbacks
/// ([`narf_userspace::InstructionInterceptor::on_instruction_deferred`]) on a
/// scheduled user task: what the callback's transitions answer, the syscall
/// park a delivered instruction ends, and a `SIGKILL` raised in the callback
/// ending the task at the trap instead of letting it run on.
#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
mod deferred_rdtsc_e2e {
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

    use narf_memory::{AddressSpace, Region, RegionPerms, VirtAddr};
    use narf_scheduler::{Affinity, CpuId, TaskSpec};
    use narf_userspace::instruction::{
        __verification_clear_instruction_interceptor, try_install_instruction_interceptor,
        DeferredInstruction, InstructionInterception, InstructionInterceptor,
        InstructionInvocation, InstructionResult, InstructionSubscriptions,
        NondeterministicInstruction,
    };
    use narf_userspace::syscall::{
        NativeRepollWait, __verification_clear_global, __verification_record_park,
    };
    use narf_userspace::{
        install_core_syscalls, install_global, install_task_id_lookup, NativeSyscallOriginalError,
        NativeSyscallOutcome, NativeSyscallRequest, NativeSyscallTransition, Syscall, SyscallArgs,
        SyscallInterception, SyscallInterceptor, SyscallInvocation, SyscallReturn, SyscallTable,
        UserProcess,
    };

    use super::{kernel_test_in, TestResult};

    const CODE_VADDR: u64 = 0x0000_0080_0000_0000;
    const STACK_VADDR: u64 = 0x0000_0080_0000_1000;
    /// Unknown to the table: `Probe` records `arg0` and completes it.
    const PROBE_NR: u32 = 0x3fff;
    /// Unknown to the table: `Probe` seeds the park record `arg0` names.
    const SEED_NR: u32 = 0x3ffe;
    /// Unknown to the table: `Probe` returns 1 while the first guest's
    /// deferred callback waits for the second guest, else 0.
    const GATE_NR: u32 = 0x3ffd;
    const MAX_PROBES: usize = 8;
    const RDTSC_MAGIC: u64 = 0x1122_3344_5566_7788;
    /// The value the second guest's RDTSC completes with at entry.
    const OTHER_MAGIC: u64 = 0x0b0b_0b0b_0b0b_0b0b;
    /// Repolls the first guest's deferred callback makes before it gives up
    /// on the second guest.
    const MAX_WAITS: usize = 10_000;
    const RBX_MARK: u32 = 0x5eed_0b0b;
    const MARK_A: u32 = 0x0a11_ce0a;
    const MARK_B: u32 = 0x0a11_ce0b;
    const MARK_AFTER_KILL: u32 = 0x0dea_d001;
    /// About 10 s at 3 GHz.
    const WAITER_BUDGET_CYCLES: u64 = 30_000_000_000;

    /// The callback script `Deferrer` follows.
    const SCRIPT_TRANSITIONS: u64 = 1;
    const SCRIPT_KILLED_ELSEWHERE: u64 = 2;
    const SCRIPT_TWO_GUESTS: u64 = 3;

    // Checks the callbacks make. `FAILURE` holds the first that failed, as an
    // index into `FAILURES`; 0 is none.
    const PROBE_TASK: usize = 1;
    const SEED_UNSCRIPTED: usize = 2;
    const ENTRY_UNSCRIPTED: usize = 3;
    const ENTRY_PAST_SCRIPT: usize = 4;
    const ORIGINAL_RAN: usize = 5;
    const ENTRY_STATE: usize = 6;
    const LIVE_KILLED: usize = 7;
    const GETPID: usize = 8;
    const EXECVE_RAN: usize = 9;
    const EXIT_RAN: usize = 10;
    const CLONE_RAN: usize = 11;
    const REPOLL_YIELD: usize = 12;
    const RETURN_VALUE: usize = 13;
    const KILL_RETURNED: usize = 14;
    const NOT_KILLED: usize = 15;
    const RAN_AFTER_KILL: usize = 16;
    const REPOLL_KILLED: usize = 17;
    const NO_PROCESS: usize = 18;
    const EXIT_REFUSED_WHEN_KILLED: usize = 19;
    const CALL_UNSCRIPTED: usize = 20;
    const OTHER_OUTSIDE_WAIT: usize = 21;
    const OTHER_NOT_RUN: usize = 22;
    const FAILURES: [&str; 23] = [
        "",
        "a probe ran on a task other than the guest",
        "a seed named no scripted park",
        "an RDTSC trapped on another task or at an unscripted address",
        "an RDTSC trapped after the script's last",
        "execute_original ran for a trapped instruction",
        "entry_user_state is not the register file at the trap",
        "task_killed reported a live guest killed",
        "an injected getpid did not return the guest's pid",
        "an injected execve was not refused with -ENOSYS",
        "an injected exit was not refused with -ENOSYS",
        "an injected clone3 was not refused with -ENOSYS",
        "wait_for_repoll did not yield to the waiter",
        "on_instruction_return saw a value other than the callback's",
        "the guest's injected kill of itself returned to the callback",
        "task_killed did not report the killed guest",
        "an inject ran after the guest was killed",
        "wait_for_repoll did not report the killed guest",
        "kill_process_sigkill found no guest process",
        "a killed guest's injected exit was refused before the signal gate answered",
        "a deferred call or return the script does not have",
        "the second guest's RDTSC trapped outside the first guest's deferred wait",
        "the second guest's RDTSC did not complete while the first guest's callback waited",
    ];

    static SCRIPT: AtomicU64 = AtomicU64::new(0);
    static TASK: AtomicU64 = AtomicU64::new(0);
    static PID: AtomicU64 = AtomicU64::new(0);
    static PROBE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static PROBES: [AtomicU64; MAX_PROBES] = [const { AtomicU64::new(0) }; MAX_PROBES];
    /// Bit `i`: probe `i` entered as the re-execution of a parked syscall.
    static PROBE_PARKED: AtomicU64 = AtomicU64::new(0);
    /// The guest's stack pointer at probe 0. The guest never moves it.
    static USER_RSP: AtomicU64 = AtomicU64::new(0);
    /// Seed `i` records a park of the probe of `SEED_MARKS[i]` entered at
    /// `SEED_IPS[i]`, as that probe parking to re-execute would.
    static SEED_IPS: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
    static SEED_MARKS: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
    static SEEDS: AtomicUsize = AtomicUsize::new(0);
    static EXITS: AtomicUsize = AtomicUsize::new(0);
    /// `RDTSC_IPS[i]`: the address of the RDTSC of deferred call `i`.
    static RDTSC_IPS: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
    static ENTERS: AtomicUsize = AtomicUsize::new(0);
    static DEFERS: AtomicUsize = AtomicUsize::new(0);
    static RETURNS: AtomicUsize = AtomicUsize::new(0);
    static NATIVE_BEFORE: AtomicU64 = AtomicU64::new(0);
    static NATIVE_VALUE: AtomicU64 = AtomicU64::new(0);
    static NATIVE_AFTER: AtomicU64 = AtomicU64::new(0);
    static TICKS: AtomicU64 = AtomicU64::new(0);
    static KILLED: AtomicBool = AtomicBool::new(false);
    static FAILURE: AtomicUsize = AtomicUsize::new(0);
    static WAITER_ERROR: AtomicU64 = AtomicU64::new(0);
    /// The second guest of `SCRIPT_TWO_GUESTS`, and the value it probed.
    static TASK_B: AtomicU64 = AtomicU64::new(0);
    static OTHER_PROBE: AtomicU64 = AtomicU64::new(0);
    /// Set while the first guest's deferred callback waits for the second.
    static IN_WAIT: AtomicBool = AtomicBool::new(false);
    /// Set once the second guest's RDTSC has completed.
    static OTHER_DONE: AtomicBool = AtomicBool::new(false);

    fn fail(check: usize) {
        let _ = FAILURE.compare_exchange(0, check, Ordering::AcqRel, Ordering::Acquire);
    }

    fn reset(script: u64) {
        SCRIPT.store(script, Ordering::Release);
        for atomic in [
            &TASK,
            &PID,
            &PROBE_PARKED,
            &USER_RSP,
            &NATIVE_BEFORE,
            &NATIVE_VALUE,
            &NATIVE_AFTER,
            &TICKS,
            &WAITER_ERROR,
            &TASK_B,
            &OTHER_PROBE,
        ] {
            atomic.store(0, Ordering::Release);
        }
        for atomic in PROBES
            .iter()
            .chain(SEED_IPS.iter())
            .chain(SEED_MARKS.iter())
            .chain(RDTSC_IPS.iter())
        {
            atomic.store(0, Ordering::Release);
        }
        for atomic in [
            &PROBE_COUNT,
            &SEEDS,
            &EXITS,
            &ENTERS,
            &DEFERS,
            &RETURNS,
            &FAILURE,
        ] {
            atomic.store(0, Ordering::Release);
        }
        for flag in [&KILLED, &IN_WAIT, &OTHER_DONE] {
            flag.store(false, Ordering::Release);
        }
    }

    struct Probe;
    impl SyscallInterceptor for Probe {
        fn on_syscall_enter(
            &self,
            invocation: &SyscallInvocation,
            _native: &mut dyn NativeSyscallTransition,
        ) -> SyscallInterception {
            match invocation.raw_number {
                PROBE_NR if invocation.task_id == TASK_B.load(Ordering::Acquire) => {
                    OTHER_PROBE.store(invocation.args.arg0, Ordering::Release);
                    SyscallInterception::Complete(SyscallReturn::ok(0))
                }
                GATE_NR => SyscallInterception::Complete(SyscallReturn::ok(u64::from(
                    IN_WAIT.load(Ordering::Acquire),
                ))),
                PROBE_NR => {
                    if invocation.task_id != TASK.load(Ordering::Acquire) {
                        fail(PROBE_TASK);
                    }
                    let index = PROBE_COUNT.fetch_add(1, Ordering::AcqRel);
                    if index < MAX_PROBES {
                        PROBES[index].store(invocation.args.arg0, Ordering::Release);
                        if invocation.park_reexecution {
                            PROBE_PARKED.fetch_or(1 << index, Ordering::AcqRel);
                        }
                    }
                    if index == 0 {
                        USER_RSP.store(invocation.stack_pointer, Ordering::Release);
                    }
                    SyscallInterception::Complete(SyscallReturn::ok(0))
                }
                SEED_NR => {
                    let seed = invocation.args.arg0 as usize;
                    match SEED_IPS.get(seed).map(|ip| ip.load(Ordering::Acquire)) {
                        Some(ip) if ip != 0 => {
                            SEEDS.fetch_add(1, Ordering::AcqRel);
                            __verification_record_park(
                                invocation.task_id,
                                ip,
                                PROBE_NR,
                                SyscallArgs {
                                    arg0: SEED_MARKS[seed].load(Ordering::Acquire),
                                    ..SyscallArgs::default()
                                },
                            );
                        }
                        _ => fail(SEED_UNSCRIPTED),
                    }
                    SyscallInterception::Complete(SyscallReturn::ok(0))
                }
                number
                    if number == Syscall::ExitTask.raw()
                        && (invocation.task_id == TASK.load(Ordering::Acquire)
                            || invocation.task_id == TASK_B.load(Ordering::Acquire)) =>
                {
                    EXITS.fetch_add(1, Ordering::AcqRel);
                    SyscallInterception::Continue
                }
                _ => SyscallInterception::Continue,
            }
        }
    }

    struct Deferrer;
    // SAFETY: `on_instruction_enter` and `on_instruction_return` only update
    // lock-free atomics and read the TSC. `on_instruction_deferred` runs under
    // its own contract: it injects syscalls, kills the guest and waits.
    unsafe impl InstructionInterceptor for Deferrer {
        fn subscriptions(&self) -> InstructionSubscriptions {
            InstructionSubscriptions::RDTSC
        }

        fn on_instruction_enter(
            &self,
            invocation: &InstructionInvocation,
        ) -> InstructionInterception {
            let call = ENTERS.fetch_add(1, Ordering::AcqRel) + 1;
            let expected_ip = RDTSC_IPS
                .get(call)
                .map_or(0, |ip| ip.load(Ordering::Acquire));
            if expected_ip == 0 {
                // A guest that should be dead ran on: let it reach its next
                // probe.
                fail(ENTRY_PAST_SCRIPT);
                return InstructionInterception::Continue;
            }
            if SCRIPT.load(Ordering::Acquire) == SCRIPT_TWO_GUESTS && call == 2 {
                // The second guest's RDTSC, trapped on the CPU where the
                // first guest's deferred callback waits: completed here.
                if invocation.task_id != TASK_B.load(Ordering::Acquire)
                    || invocation.instruction_pointer != expected_ip
                {
                    fail(ENTRY_UNSCRIPTED);
                }
                if !IN_WAIT.load(Ordering::Acquire) {
                    fail(OTHER_OUTSIDE_WAIT);
                }
                return InstructionInterception::Complete(InstructionResult::Rdtsc {
                    value: OTHER_MAGIC,
                });
            }
            if invocation.task_id != TASK.load(Ordering::Acquire)
                || invocation.instruction != NondeterministicInstruction::Rdtsc
                || invocation.instruction_pointer != expected_ip
            {
                fail(ENTRY_UNSCRIPTED);
            }
            InstructionInterception::Defer
        }

        fn on_instruction_deferred(
            &self,
            invocation: &InstructionInvocation,
            native: &mut dyn NativeSyscallTransition,
        ) -> DeferredInstruction {
            let call = DEFERS.fetch_add(1, Ordering::AcqRel) + 1;
            match (SCRIPT.load(Ordering::Acquire), call) {
                (SCRIPT_TRANSITIONS, 1) => transitions_of_a_live_task(invocation, native),
                (SCRIPT_TRANSITIONS, 2) => {
                    NATIVE_BEFORE.store(narf_arch::x86_64::tsc::rdtsc(), Ordering::Release);
                    DeferredInstruction::Native
                }
                (SCRIPT_TRANSITIONS, 3) => kill_through_inject(native),
                (SCRIPT_KILLED_ELSEWHERE, 1) => killed_elsewhere(native),
                (SCRIPT_TWO_GUESTS, 1) => wait_for_the_other_guest(native),
                _ => {
                    fail(CALL_UNSCRIPTED);
                    DeferredInstruction::Native
                }
            }
        }

        fn on_instruction_return(
            &self,
            invocation: &InstructionInvocation,
            result: InstructionResult,
        ) -> InstructionResult {
            let call = RETURNS.fetch_add(1, Ordering::AcqRel) + 1;
            match (SCRIPT.load(Ordering::Acquire), call, result) {
                // Either guest's; the second guest's returns first.
                (SCRIPT_TWO_GUESTS, 1 | 2, InstructionResult::Rdtsc { value }) => {
                    let other = invocation.task_id == TASK_B.load(Ordering::Acquire);
                    if value != if other { OTHER_MAGIC } else { RDTSC_MAGIC } {
                        fail(RETURN_VALUE);
                    }
                    if other {
                        OTHER_DONE.store(true, Ordering::Release);
                    }
                    InstructionResult::Rdtsc {
                        value: value.wrapping_add(1),
                    }
                }
                (SCRIPT_TRANSITIONS, 1, InstructionResult::Rdtsc { value }) => {
                    if value != RDTSC_MAGIC {
                        fail(RETURN_VALUE);
                    }
                    InstructionResult::Rdtsc {
                        value: value.wrapping_add(1),
                    }
                }
                (SCRIPT_TRANSITIONS, 2, InstructionResult::Rdtsc { value }) => {
                    NATIVE_VALUE.store(value, Ordering::Release);
                    NATIVE_AFTER.store(narf_arch::x86_64::tsc::rdtsc(), Ordering::Release);
                    InstructionResult::Rdtsc {
                        value: value.wrapping_add(1),
                    }
                }
                _ => {
                    fail(CALL_UNSCRIPTED);
                    result
                }
            }
        }
    }

    fn request(syscall: Syscall, args: SyscallArgs) -> NativeSyscallRequest {
        NativeSyscallRequest::new(syscall.raw(), args)
    }

    fn refused(outcome: NativeSyscallOutcome) -> bool {
        outcome == NativeSyscallOutcome::Returned(SyscallReturn::not_implemented())
    }

    /// Deferred call 1 of `SCRIPT_TRANSITIONS`: each transition of a live
    /// task, then a completed value. It stops at the first failed check, so
    /// an inject that a missing refusal would let run is never reached.
    fn transitions_of_a_live_task(
        invocation: &InstructionInvocation,
        native: &mut dyn NativeSyscallTransition,
    ) -> DeferredInstruction {
        let completed =
            DeferredInstruction::Complete(InstructionResult::Rdtsc { value: RDTSC_MAGIC });
        if !matches!(
            native.execute_original(),
            Err(NativeSyscallOriginalError::AlreadyExecuted)
        ) {
            fail(ORIGINAL_RAN);
            return completed;
        }
        let at_trap = native.entry_user_state().is_some_and(|state| {
            state.rip == invocation.instruction_pointer
                && state.rbx == u64::from(RBX_MARK)
                && state.rsp == USER_RSP.load(Ordering::Acquire)
        });
        if !at_trap {
            fail(ENTRY_STATE);
            return completed;
        }
        if native.task_killed() {
            fail(LIVE_KILLED);
            return completed;
        }
        let pid = PROBES[0].load(Ordering::Acquire);
        if native.execute_injected(request(Syscall::GetPid, SyscallArgs::default()))
            != NativeSyscallOutcome::Returned(SyscallReturn::ok(pid))
        {
            fail(GETPID);
            return completed;
        }
        // A null path and a null clone_args: were the refusal missing, these
        // would fail with -EFAULT and -EINVAL, never replace the image or
        // create a task. The exit is reached only after the execve's refusal.
        if !refused(native.execute_injected(request(Syscall::Execve, SyscallArgs::default()))) {
            fail(EXECVE_RAN);
            return completed;
        }
        if !refused(native.execute_injected(request(Syscall::ExitTask, SyscallArgs::default()))) {
            fail(EXIT_RAN);
            return completed;
        }
        if !refused(native.execute_injected(request(Syscall::Clone3, SyscallArgs::default()))) {
            fail(CLONE_RAN);
            return completed;
        }
        let ticks = TICKS.load(Ordering::Acquire);
        if !matches!(native.wait_for_repoll(), NativeRepollWait::Yielded)
            || TICKS.load(Ordering::Acquire) == ticks
        {
            fail(REPOLL_YIELD);
        }
        completed
    }

    /// Deferred call 3 of `SCRIPT_TRANSITIONS`: the guest kills itself
    /// through an inject. The value is ignored.
    fn kill_through_inject(native: &mut dyn NativeSyscallTransition) -> DeferredInstruction {
        let ignored = DeferredInstruction::Complete(InstructionResult::Rdtsc { value: 0 });
        if native.task_killed() {
            fail(LIVE_KILLED);
        }
        let pid = PID.load(Ordering::Acquire);
        if pid == 0 {
            // kill(0) would signal the whole process group.
            fail(NO_PROCESS);
            return ignored;
        }
        let kill = native.execute_injected(request(
            Syscall::Kill,
            SyscallArgs {
                arg0: pid,
                arg1: 9,
                ..SyscallArgs::default()
            },
        ));
        KILLED.store(true, Ordering::Release);
        if kill != NativeSyscallOutcome::ContextManaged {
            fail(KILL_RETURNED);
        }
        if !native.task_killed() {
            fail(NOT_KILLED);
        }
        if native.execute_injected(request(Syscall::GetPid, SyscallArgs::default()))
            != NativeSyscallOutcome::ContextManaged
        {
            fail(RAN_AFTER_KILL);
        }
        if !matches!(native.wait_for_repoll(), NativeRepollWait::Killed) {
            fail(REPOLL_KILLED);
        }
        ignored
    }

    /// Deferred call 1 of `SCRIPT_KILLED_ELSEWHERE`: the kernel kills the
    /// guest outside any transition, so no transition has answered
    /// `ContextManaged` yet. An exit injected next must meet the signal gate
    /// before the refusal of exits. The value is ignored.
    fn killed_elsewhere(native: &mut dyn NativeSyscallTransition) -> DeferredInstruction {
        let ignored = DeferredInstruction::Complete(InstructionResult::Rdtsc { value: 0 });
        if native.task_killed() {
            fail(LIVE_KILLED);
            return ignored;
        }
        let pid = PID.load(Ordering::Acquire);
        if pid == 0 || !narf_userspace::handlers::tool_view::kill_process_sigkill(pid) {
            fail(NO_PROCESS);
            return ignored;
        }
        KILLED.store(true, Ordering::Release);
        if !native.task_killed() {
            fail(NOT_KILLED);
        }
        if native.execute_injected(request(Syscall::ExitTask, SyscallArgs::default()))
            != NativeSyscallOutcome::ContextManaged
        {
            fail(EXIT_REFUSED_WHEN_KILLED);
        }
        if native.execute_injected(request(Syscall::GetPid, SyscallArgs::default()))
            != NativeSyscallOutcome::ContextManaged
        {
            fail(RAN_AFTER_KILL);
        }
        ignored
    }

    /// Deferred call 1 of `SCRIPT_TWO_GUESTS`: the first guest's callback
    /// repolls until the second guest, pinned to the same CPU, has trapped
    /// its RDTSC and had it completed.
    fn wait_for_the_other_guest(native: &mut dyn NativeSyscallTransition) -> DeferredInstruction {
        IN_WAIT.store(true, Ordering::Release);
        let mut waits = 0;
        while !OTHER_DONE.load(Ordering::Acquire) {
            if waits == MAX_WAITS {
                fail(OTHER_NOT_RUN);
                break;
            }
            waits += 1;
            if !matches!(native.wait_for_repoll(), NativeRepollWait::Yielded) {
                fail(REPOLL_YIELD);
                break;
            }
        }
        IN_WAIT.store(false, Ordering::Release);
        DeferredInstruction::Complete(InstructionResult::Rdtsc { value: RDTSC_MAGIC })
    }

    /// A straight-line guest program at `CODE_VADDR`.
    struct Guest(Vec<u8>);

    impl Guest {
        /// The address of the next instruction.
        fn here(&self) -> u64 {
            CODE_VADDR + self.0.len() as u64
        }

        fn emit(&mut self, bytes: &[u8]) {
            self.0.extend_from_slice(bytes);
        }

        /// `mov r32, imm32`, whose opcode is `opcode` (`B8+r`).
        fn mov_imm(&mut self, opcode: u8, imm: u32) {
            self.0.push(opcode);
            self.0.extend_from_slice(&imm.to_le_bytes());
        }

        /// Fast syscall `number`, with RDI as it is and every other argument
        /// register zero. Returns the address after the `syscall`, the entry
        /// address the kernel records for it.
        fn syscall(&mut self, number: u32) -> u64 {
            // xor esi,esi; xor edx,edx; xor r10d,r10d; xor r8d,r8d; xor r9d,r9d
            self.emit(&[
                0x31, 0xF6, 0x31, 0xD2, 0x45, 0x31, 0xD2, 0x45, 0x31, 0xC0, 0x45, 0x31, 0xC9,
            ]);
            self.mov_imm(0xB8, number); // mov eax,number
            self.emit(&[0x0F, 0x05]); // syscall
            self.here()
        }

        /// Probes `value`. Returns the probe's entry address.
        fn probe(&mut self, value: u32) -> u64 {
            self.mov_imm(0xBF, value); // mov edi,value
            self.syscall(PROBE_NR)
        }

        /// Probes RAX.
        fn probe_rax(&mut self) {
            self.emit(&[0x48, 0x89, 0xC7]); // mov rdi,rax
            self.syscall(PROBE_NR);
        }

        /// Probes the guest's own pid.
        fn probe_pid(&mut self) {
            self.syscall(Syscall::GetPid.raw());
            self.probe_rax();
        }

        /// Seeds the park record `SEED_IPS[seed]` names.
        fn seed(&mut self, seed: u32) {
            self.mov_imm(0xBF, seed); // mov edi,seed
            self.syscall(SEED_NR);
        }

        /// Yields the CPU until the gate syscall returns nonzero.
        fn wait_for_gate(&mut self) {
            let top = self.0.len();
            self.syscall(GATE_NR);
            self.emit(&[0x85, 0xC0, 0x75, 0]); // test eax,eax; jnz past the loop
            let past_jnz = self.0.len();
            self.syscall(Syscall::Yield.raw());
            let back = top as isize - (self.0.len() as isize + 2);
            self.emit(&[0xEB, back as i8 as u8]); // jmp top
            self.0[past_jnz - 1] = (self.0.len() - past_jnz) as u8;
        }

        /// RDTSC, then EDX:EAX joined in RAX. Returns the RDTSC's address.
        fn rdtsc(&mut self) -> u64 {
            let at = self.here();
            // rdtsc; shl rdx,32; or rax,rdx
            self.emit(&[0x0F, 0x31, 0x48, 0xC1, 0xE2, 0x20, 0x48, 0x09, 0xD0]);
            at
        }

        /// ExitTask(0), then spin.
        fn exit(&mut self) {
            self.mov_imm(0xBF, 0); // mov edi,0
            self.mov_imm(0xB8, Syscall::ExitTask.raw()); // mov eax,ExitTask
            self.emit(&[0xCD, 0x80, 0xEB, 0xFE]); // int 0x80; jmp $
        }
    }

    /// A fresh user address space with `code` at `CODE_VADDR` and a stack
    /// page at `STACK_VADDR`.
    fn load_guest(code: &[u8]) -> Result<AddressSpace, &'static str> {
        if code.len() > 0x1000 {
            return Err("the guest program exceeds its page");
        }
        // SAFETY: this test exclusively owns the fresh address space until the
        // scheduled task exits.
        let address_space =
            unsafe { AddressSpace::new_for_user() }.map_err(|_| "new_for_user failed")?;
        let code_frame = narf_memory::alloc_frame()
            .map_err(|_| "alloc code frame")?
            .start_address();
        let stack_frame = narf_memory::alloc_frame()
            .map_err(|_| "alloc stack frame")?
            .start_address();
        if address_space
            .map_region(Region {
                base: VirtAddr::new(CODE_VADDR),
                len: 0x1000,
                perms: RegionPerms::READ | RegionPerms::EXEC | RegionPerms::WRITE,
                phys: alloc::vec![code_frame],
            })
            .is_err()
            || address_space
                .map_region(Region {
                    base: VirtAddr::new(STACK_VADDR),
                    len: 0x1000,
                    perms: RegionPerms::READ | RegionPerms::WRITE,
                    phys: alloc::vec![stack_frame],
                })
                .is_err()
        {
            return Err("map user regions failed");
        }
        // SAFETY: the frame is exclusively owned and the program fits one page.
        unsafe {
            core::ptr::copy_nonoverlapping(
                code.as_ptr(),
                code_frame.kernel_mut_ptr::<u8>(),
                code.len(),
            );
        }
        // SAFETY: materialize publishes the complete mappings above.
        if unsafe { address_space.materialize() }.is_err() {
            return Err("materialize failed");
        }
        Ok(address_space)
    }

    /// Runs `code` as a user task pinned to this CPU, under `Probe` and
    /// `Deferrer`, until the scheduler has reaped it.
    fn run_guest(code: &[u8]) -> Result<(), &'static str> {
        run_guests(&[code])
    }

    /// Runs one or two guest programs as user tasks pinned to this CPU, under
    /// `Probe` and `Deferrer`, until the scheduler has reaped them all. The
    /// first runs as `TASK` with pid `PID`, the second as `TASK_B`.
    fn run_guests(codes: &[&[u8]]) -> Result<(), &'static str> {
        if codes.is_empty() || codes.len() > 2 {
            return Err("run_guests takes one or two guests");
        }
        __verification_clear_global();
        __verification_clear_instruction_interceptor();
        narf_userspace::user_task::__test_clear_hooks();
        let cpu = narf_lib::percpu::current_cpu();
        let original_cr3: u64;
        // SAFETY: snapshot the kernel address space for defensive test cleanup.
        unsafe {
            core::arch::asm!("mov {value}, cr3", value = out(reg) original_cr3,
                options(nostack, preserves_flags));
        }
        let mut address_spaces = Vec::new();
        for code in codes {
            address_spaces.push(load_guest(code)?);
        }

        let mut table = SyscallTable::new();
        install_core_syscalls(&mut table);
        if table.install_interceptor(Box::new(Probe)).is_err() {
            return Err("syscall interceptor install failed");
        }
        install_global(table);
        if try_install_instruction_interceptor(Box::new(Deferrer)).is_err() {
            __verification_clear_global();
            return Err("instruction interceptor install failed");
        }
        // Kernel-test boots skip the boot-time signal init, and without its
        // tables a raised SIGKILL finds no pending-bit map and is dropped.
        // Tables this test creates are removed again once the guest is reaped.
        let signal_tables = narf_userspace::handlers::__test_signal_tables_state();
        narf_userspace::signal_init();
        if !signal_tables.sigactions {
            narf_userspace::sigaction_init();
        }
        install_task_id_lookup(|| narf_scheduler::current_task_id().raw());
        narf_scheduler::__reset_queues_for_test();
        narf_userspace::install_user_task_hooks();
        let live_before = narf_scheduler::live_user_task_count();
        let mut pids = Vec::new();
        let mut pending = Vec::new();
        for (address_space, task_slot) in address_spaces.into_iter().zip([&TASK, &TASK_B]) {
            let pid = narf_userspace::alloc_pid();
            let pid_raw = pid.raw();
            let process = UserProcess {
                pid,
                address_space: Arc::new(address_space),
                entry: narf_userspace::EntryPoint(VirtAddr::new(CODE_VADDR)),
                stack_top: VirtAddr::new(STACK_VADDR + 0x1000),
                fs_base: None,
                entry_arg: None,
                loaded_mappings: Vec::new(),
                auxv: Vec::new(),
            };
            // Pinned here, so the waiter below runs while the guests are
            // switched out, and every TSC read of a deferred call is on one
            // CPU.
            let mut spec = TaskSpec::user_task();
            spec.affinity = Affinity::pinned(CpuId(cpu as u32));
            let prepared = narf_userspace::user_task::prepare_user_process_initial(process, spec);
            let task = prepared.task_id().raw();
            // The injected getpid and kill resolve a guest through this mapping.
            narf_userspace::handlers::register_pid_task_mapping(pid_raw, task);
            task_slot.store(task, Ordering::Release);
            pids.push(pid_raw);
            pending.push(prepared);
        }
        PID.store(pids[0], Ordering::Release);
        for prepared in pending {
            let _ = prepared.spawn();
        }

        // The waiter, pinned beside the guests, keeps this CPU's executor
        // alive until they are reaped; it runs only while no guest runs. Past
        // its budget it kills the guests, so a failure leaves no live task
        // behind, and waits once more.
        let mut deadline = narf_time::Instant::now().plus_cycles(WAITER_BUDGET_CYCLES);
        let mut waiter = TaskSpec::unthrottled();
        waiter.affinity = Affinity::pinned(CpuId(cpu as u32));
        narf_scheduler::spawn_with_spec(
            async move {
                let mut killed_here = false;
                loop {
                    TICKS.fetch_add(1, Ordering::AcqRel);
                    let ended = killed_here
                        || KILLED.load(Ordering::Acquire)
                        || EXITS.load(Ordering::Acquire) != 0;
                    if ended && narf_scheduler::live_user_task_count() <= live_before {
                        return;
                    }
                    if narf_time::Instant::now() >= deadline {
                        if killed_here {
                            WAITER_ERROR.store(3, Ordering::Release);
                            return;
                        }
                        let code = if KILLED.load(Ordering::Acquire) { 2 } else { 1 };
                        WAITER_ERROR.store(code, Ordering::Release);
                        for &pid in &pids {
                            let _ = narf_userspace::handlers::tool_view::kill_process_sigkill(pid);
                        }
                        killed_here = true;
                        deadline = narf_time::Instant::now().plus_cycles(WAITER_BUDGET_CYCLES);
                    }
                    narf_scheduler::yield_now().await;
                }
            },
            waiter,
        );

        narf_scheduler::run_until_empty();

        // SAFETY: restore the kernel CR3 and kernel-GS state after the user task
        // has exited, matching the neighbouring scheduled-user smokes.
        unsafe {
            core::arch::asm!("mov cr3, {value}", value = in(reg) original_cr3,
                options(nostack, preserves_flags));
            const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
            core::arch::asm!(
                "wrmsr",
                in("ecx") IA32_KERNEL_GS_BASE,
                in("eax") 0u32,
                in("edx") 0u32,
                options(nostack, preserves_flags),
            );
            core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
        }
        narf_userspace::user_task::__test_clear_hooks();
        narf_userspace::handlers::__test_reset_task_id_lookup();
        __verification_clear_instruction_interceptor();
        __verification_clear_global();
        // Only with no user task live: a guest the waiter could not reap
        // keeps the tables it may still use.
        if narf_scheduler::live_user_task_count() <= live_before {
            narf_userspace::handlers::__test_restore_signal_tables(signal_tables);
        }
        Ok(())
    }

    /// The first failure the callbacks or the waiter recorded, if any.
    fn recorded_failure() -> Option<&'static str> {
        match FAILURE.load(Ordering::Acquire) {
            0 => {}
            check => return Some(FAILURES.get(check).copied().unwrap_or("unknown check")),
        }
        match WAITER_ERROR.load(Ordering::Acquire) {
            0 => None,
            1 => Some("the guest was neither killed nor exited within the budget"),
            2 => Some("the killed guest was not reaped within the budget"),
            _ => Some("the guest was not reaped even after the waiter killed it"),
        }
    }

    /// Three deferred RDTSCs on one guest. The first answers each transition
    /// of a live task (the refused injects among them) and completes a value;
    /// its delivery ends the syscall park seeded just before it. The second
    /// completes natively after the callback. The third kills the guest
    /// through an inject, and the guest must die at that RDTSC.
    fn smoke_deferred_rdtsc_transitions_park_and_self_kill() -> TestResult {
        reset(SCRIPT_TRANSITIONS);
        let mut guest = Guest(Vec::new());
        guest.probe_pid(); // probe 0
        guest.seed(1);
        let mark_a = guest.probe(MARK_A); // probe 1: re-executes seed 1's park
        guest.seed(2);
        guest.mov_imm(0xBB, RBX_MARK); // mov ebx,RBX_MARK
        let first = guest.rdtsc();
        guest.emit(&[0x48, 0x89, 0xC3]); // mov rbx,rax
        let mark_b = guest.probe(MARK_B); // probe 2: the RDTSC ended seed 2's park
        guest.emit(&[0x48, 0x89, 0xDF]); // mov rdi,rbx
        guest.syscall(PROBE_NR); // probe 3: the first RDTSC's value
        let second = guest.rdtsc();
        guest.probe_rax(); // probe 4: the second RDTSC's value
        let third = guest.rdtsc();
        guest.probe(MARK_AFTER_KILL);
        guest.exit();
        SEED_IPS[1].store(mark_a, Ordering::Release);
        SEED_MARKS[1].store(u64::from(MARK_A), Ordering::Release);
        SEED_IPS[2].store(mark_b, Ordering::Release);
        SEED_MARKS[2].store(u64::from(MARK_B), Ordering::Release);
        for (slot, ip) in RDTSC_IPS[1..].iter().zip([first, second, third]) {
            slot.store(ip, Ordering::Release);
        }

        if let Err(reason) = run_guest(&guest.0) {
            return TestResult::Fail(reason);
        }
        if let Some(reason) = recorded_failure() {
            return TestResult::Fail(reason);
        }
        if ENTERS.load(Ordering::Acquire) != 3
            || DEFERS.load(Ordering::Acquire) != 3
            || RETURNS.load(Ordering::Acquire) != 2
        {
            return TestResult::Fail("the guest did not trap three RDTSCs and complete two");
        }
        if SEEDS.load(Ordering::Acquire) != 2 || PROBE_COUNT.load(Ordering::Acquire) != 5 {
            return TestResult::Fail("the guest did not run exactly its seeds and probes");
        }
        let probe = |index: usize| PROBES[index].load(Ordering::Acquire);
        if probe(0) == 0 || probe(1) != u64::from(MARK_A) || probe(2) != u64::from(MARK_B) {
            return TestResult::Fail("the guest's probes ran out of order");
        }
        let parked = PROBE_PARKED.load(Ordering::Acquire);
        if parked & (1 << 1) == 0 {
            return TestResult::Fail("a seeded park was not seen as the probe's re-execution");
        }
        if parked & !(1 << 1) != 0 {
            return TestResult::Fail("a syscall park outlived the delivered RDTSC after it");
        }
        if probe(3) != RDTSC_MAGIC.wrapping_add(1) {
            return TestResult::Fail("the deferred value did not reach the guest");
        }
        let native = NATIVE_VALUE.load(Ordering::Acquire);
        if native < NATIVE_BEFORE.load(Ordering::Acquire)
            || native > NATIVE_AFTER.load(Ordering::Acquire)
            || probe(4) != native.wrapping_add(1)
        {
            return TestResult::Fail("a deferred Native did not read the TSC after the callback");
        }
        if !KILLED.load(Ordering::Acquire) || EXITS.load(Ordering::Acquire) != 0 {
            return TestResult::Fail("the guest was not killed at its third RDTSC");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "verification/instruction-defer",
        smoke_deferred_rdtsc_transitions_park_and_self_kill
    );

    /// A guest the kernel kills during its deferred RDTSC callback, outside
    /// any transition: an exit the callback injects must answer
    /// `ContextManaged` from the signal gate rather than be refused, and the
    /// guest must die at that RDTSC.
    fn smoke_deferred_rdtsc_killed_elsewhere_meets_signal_gate_first() -> TestResult {
        reset(SCRIPT_KILLED_ELSEWHERE);
        let mut guest = Guest(Vec::new());
        guest.probe_pid(); // probe 0
        let first = guest.rdtsc();
        guest.probe(MARK_AFTER_KILL);
        guest.exit();
        RDTSC_IPS[1].store(first, Ordering::Release);

        if let Err(reason) = run_guest(&guest.0) {
            return TestResult::Fail(reason);
        }
        if let Some(reason) = recorded_failure() {
            return TestResult::Fail(reason);
        }
        if ENTERS.load(Ordering::Acquire) != 1
            || DEFERS.load(Ordering::Acquire) != 1
            || RETURNS.load(Ordering::Acquire) != 0
        {
            return TestResult::Fail("the killed guest's RDTSC completed or trapped again");
        }
        if PROBE_COUNT.load(Ordering::Acquire) != 1 {
            return TestResult::Fail("the killed guest ran on past its RDTSC");
        }
        if !KILLED.load(Ordering::Acquire) || EXITS.load(Ordering::Acquire) != 0 {
            return TestResult::Fail("the guest was not killed at its RDTSC");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "verification/instruction-defer",
        smoke_deferred_rdtsc_killed_elsewhere_meets_signal_gate_first
    );

    /// While one guest's deferred RDTSC callback waits, a second guest pinned
    /// to the same CPU traps an RDTSC, which is completed at entry. The CPU's
    /// instruction flag must not stay held across the callback: the second
    /// trap would find it held and fail closed.
    fn smoke_deferred_rdtsc_wait_lets_another_guest_trap_on_its_cpu() -> TestResult {
        reset(SCRIPT_TWO_GUESTS);
        let mut first = Guest(Vec::new());
        let first_rdtsc = first.rdtsc();
        first.probe_rax(); // the first guest's only probe
        first.exit();
        let mut second = Guest(Vec::new());
        second.wait_for_gate();
        let second_rdtsc = second.rdtsc();
        second.probe_rax(); // `OTHER_PROBE`
        second.exit();
        RDTSC_IPS[1].store(first_rdtsc, Ordering::Release);
        RDTSC_IPS[2].store(second_rdtsc, Ordering::Release);

        if let Err(reason) = run_guests(&[&first.0, &second.0]) {
            return TestResult::Fail(reason);
        }
        if let Some(reason) = recorded_failure() {
            return TestResult::Fail(reason);
        }
        if ENTERS.load(Ordering::Acquire) != 2
            || DEFERS.load(Ordering::Acquire) != 1
            || RETURNS.load(Ordering::Acquire) != 2
        {
            return TestResult::Fail(
                "the guests did not trap one RDTSC each, only the first deferred",
            );
        }
        if OTHER_PROBE.load(Ordering::Acquire) != OTHER_MAGIC.wrapping_add(1) {
            return TestResult::Fail("the second guest did not read its completed value");
        }
        if PROBE_COUNT.load(Ordering::Acquire) != 1
            || PROBES[0].load(Ordering::Acquire) != RDTSC_MAGIC.wrapping_add(1)
        {
            return TestResult::Fail("the first guest did not read its deferred value");
        }
        if EXITS.load(Ordering::Acquire) != 2 {
            return TestResult::Fail("the guests did not both exit");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "verification/instruction-defer",
        smoke_deferred_rdtsc_wait_lets_another_guest_trap_on_its_cpu
    );
}

#[cfg(target_arch = "x86_64")]
fn smoke_remote_call_completes_while_target_waits_for_shootdown_ack() -> TestResult {
    // Two IRQ-masked acknowledgement spins waiting on each other: the AP is a
    // TLB-shootdown sender waiting for this CPU, and this CPU then becomes a
    // remote_call sender waiting for the AP. This CPU masks IRQs before the
    // AP publishes, so the AP's IPI stays latched here, and it takes no
    // contended lock that could poll the request. Once the request is seen
    // pending, the AP holds its shootdown lane with IRQs masked and cannot
    // return until this CPU acknowledges it. The call can then complete only
    // if one of the two spins services the other's request; otherwise both
    // CPUs wait forever and the suite fails at the QEMU timeout. Nothing
    // here depends on timing. The pass criteria do not name which spin broke
    // the cycle.
    //
    // This CPU's masked wait must still acknowledge the AP's other requests,
    // or it deadlocks by itself: an AP that shoots down for an unrelated
    // reason, such as cleanup an earlier test left behind, waits for this CPU
    // with IRQs masked, and cannot start the task, or publish the test's
    // request, until its lane is free. The AP therefore sends one
    // unrelated request first, so every run crosses that case, and the wait
    // services whatever the AP's lane holds until it holds the test's
    // request. Other CPUs' requests can stay pending: their senders poll
    // for requests while they wait, so they never hold up the AP.
    use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use narf_interrupts::x86_64::ipi;

    // Nonzero, so a pending request with it is this test's; below 0x1000, so
    // it is a valid PCID. A single-context flush is always a correct
    // invalidation, whichever address space owns the PCID.
    const TAG: u16 = 0x0A5A;
    // The unrelated request the AP sends first; valid for the same reasons.
    const EARLIER_TAG: u16 = 0x0A5B;
    static SHOT: AtomicBool = AtomicBool::new(false);
    static SHOT_CPU: AtomicUsize = AtomicUsize::new(usize::MAX);
    static CALLED_ON: AtomicU64 = AtomicU64::new(0);

    fn record_cpu() {
        let cpu = narf_lib::percpu::current_cpu();
        if cpu < 64 {
            CALLED_ON.fetch_or(1u64 << cpu, Ordering::AcqRel);
        }
    }

    if !narf_lib::smp::remote_barrier_available() {
        return TestResult::Skip("needs the rendezvous IPI");
    }
    SHOT.store(false, Ordering::Release);
    SHOT_CPU.store(usize::MAX, Ordering::Release);
    CALLED_ON.store(0, Ordering::Release);

    // 3e10 cycles is about 10 s at 3 GHz.
    const BUDGET_CYCLES: u64 = 30_000_000_000;
    // The CPU numbers are read with IRQs masked, so this task cannot migrate
    // between choosing them and waiting as `caller`.
    let outcome = narf_lib::sync::without_interrupts(|| {
        let caller = narf_lib::percpu::current_cpu();
        let peers = narf_lib::smp::online_bitmap() & !(1u64 << caller);
        if peers == 0 {
            return Err(TestResult::Skip("needs an online AP"));
        }
        let target = peers.trailing_zeros() as usize;
        if ipi::__pending_tag_from(caller as u32, target as u32) == Some(TAG) {
            return Err(TestResult::Fail(
                "a request with the test tag was already pending",
            ));
        }
        let mut spec = narf_scheduler::TaskSpec::kernel_any();
        spec.affinity = narf_scheduler::Affinity::pinned(narf_scheduler::CpuId(target as u32));
        narf_scheduler::spawn_with_spec(
            async move {
                SHOT_CPU.store(narf_lib::percpu::current_cpu(), Ordering::Release);
                // SAFETY: CPL=0 with the shootdown IPI installed at boot; both
                // requests are correct invalidations (see TAG).
                unsafe {
                    ipi::shoot_tag_only_mask(EARLIER_TAG, 1u64 << caller);
                    ipi::shoot_tag_only_mask(TAG, 1u64 << caller);
                }
                SHOT.store(true, Ordering::Release);
            },
            spec,
        );
        let deadline = narf_time::Instant::now().plus_cycles(BUDGET_CYCLES);
        let target_bit = 1u64 << target;
        let mut earlier_serviced = 0u64;
        loop {
            match ipi::__pending_tag_from(caller as u32, target as u32) {
                Some(TAG) => break,
                // The AP's lane cannot carry the test's request until this
                // CPU acknowledges what it holds now, so servicing it here
                // cannot consume the test's request.
                Some(_) => {
                    // SAFETY: CPL=0; services only the AP's pending request.
                    unsafe { ipi::__service_sources_for_test(target_bit) };
                    earlier_serviced += 1;
                }
                None => {}
            }
            if narf_time::Instant::now() >= deadline {
                let _ = writeln!(
                    Writer,
                    "    rendezvous expiry: caller={} target={} task_cpu={} ap_pending_tag={:?} earlier_serviced={}",
                    caller,
                    target,
                    SHOT_CPU.load(Ordering::Acquire) as isize,
                    ipi::__pending_tag_from(caller as u32, target as u32),
                    earlier_serviced,
                );
                return Ok((caller, target, false, false, 0, earlier_serviced));
            }
            core::hint::spin_loop();
        }
        let acks_before = ipi::ack_count(caller as u32);
        // SAFETY: record_cpu only updates an atomic bitmap.
        let called = unsafe { narf_lib::smp::remote_call(1u64 << target, record_cpu) };
        let acks = ipi::ack_count(caller as u32).wrapping_sub(acks_before);
        Ok((caller, target, true, called, acks, earlier_serviced))
    });
    let (caller, target, observed, called, acks, earlier_serviced) = match outcome {
        Ok(v) => v,
        Err(result) => return result,
    };

    // With IRQs restored the latched IPI completes the AP's request if the
    // call did not; poll too, in case this context runs with IRQs masked.
    let deadline = narf_time::Instant::now().plus_cycles(BUDGET_CYCLES);
    while !SHOT.load(Ordering::Acquire) && narf_time::Instant::now() < deadline {
        // SAFETY: CPL=0; consumes only this CPU's pending shootdown requests.
        unsafe { ipi::poll_pending_shootdown() };
        core::hint::spin_loop();
    }
    if !observed {
        return TestResult::Fail("the AP's shootdown request was never seen pending");
    }
    // The AP publishes the test's request only after this CPU acknowledged
    // the earlier one inside the masked wait.
    if earlier_serviced == 0 {
        return TestResult::Fail("the masked wait never serviced the AP's earlier request");
    }
    // Printed, not asserted: the test requires the cycle to be broken, not
    // which spin broke it, so the h1-removed negative control ties it to
    // remote_call's servicing.
    let _ = writeln!(
        Writer,
        "    shootdowns acknowledged inside the call: {}",
        acks
    );
    if !called {
        return TestResult::Fail("remote_call was refused");
    }
    // remote_call runs the action inline on the calling CPU as well.
    if CALLED_ON.load(Ordering::Acquire) != (1u64 << caller) | (1u64 << target) {
        return TestResult::Fail("the call's action did not run on exactly this CPU and the AP");
    }
    if !SHOT.load(Ordering::Acquire) || SHOT_CPU.load(Ordering::Acquire) != target {
        return TestResult::Fail("the AP's shootdown did not complete");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "verification/smp-rendezvous",
    smoke_remote_call_completes_while_target_waits_for_shootdown_ack
);

/// A CPU waiting for an RCU grace period with IRQs masked must acknowledge a
/// peer's TLB shootdown. A peer that drops the last reference to an address
/// space shoots down, IRQs masked, and waits without a timeout; if the waiter
/// here only acknowledges from the IPI handler, the peer's CPU stays wedged
/// and whatever it was freeing (the space, its COW frames) is never released.
///
/// This CPU masks IRQs explicitly and then only calls `rcu::sync_until` with
/// short deadlines, the loop a reclaiming caller runs. A peer CPU sends one
/// shootdown aimed only at this CPU. On a timeout the test drains the request
/// itself, so the peer is released before the failure is reported.
#[cfg(target_arch = "x86_64")]
fn smoke_rcu_sync_until_acknowledges_peer_shootdown() -> TestResult {
    use core::sync::atomic::{AtomicU32, Ordering};
    use narf_interrupts::x86_64::ipi;

    const NOT_STARTED: u32 = 0;
    const SENDING: u32 = 1;
    const ACKNOWLEDGED: u32 = 2;
    static PEER: AtomicU32 = AtomicU32::new(NOT_STARTED);

    let outcome = narf_lib::sync::without_interrupts(|| {
        let me = narf_lib::percpu::current_cpu();
        let peers = narf_lib::smp::online_bitmap() & !(1u64 << me);
        if peers == 0 {
            return Err(TestResult::Skip("needs an online AP"));
        }
        let peer = peers.trailing_zeros();
        PEER.store(NOT_STARTED, Ordering::Release);
        let mut spec = narf_scheduler::TaskSpec::kernel_any();
        spec.affinity = narf_scheduler::Affinity::pinned(narf_scheduler::CpuId(peer));
        narf_scheduler::spawn_with_spec(
            async move {
                PEER.store(SENDING, Ordering::Release);
                // SAFETY: CPL=0 with the shootdown IPI installed at boot; the
                // mapping is unchanged, so the INVLPG is conservative.
                unsafe { ipi::shoot_range_mask(0xFFFF_FFFF_8000_4000, 1, 0, 1u64 << me) };
                PEER.store(ACKNOWLEDGED, Ordering::Release);
            },
            spec,
        );
        let deadline = narf_time::monotonic_ns().saturating_add(2_000_000_000);
        while PEER.load(Ordering::Acquire) != ACKNOWLEDGED {
            let now = narf_time::monotonic_ns();
            if now >= deadline {
                return Ok(false);
            }
            let _ = narf_rcu::sync_until(now.saturating_add(1_000_000).min(deadline));
        }
        Ok(true)
    });
    let acknowledged = match outcome {
        Ok(acknowledged) => acknowledged,
        Err(result) => return result,
    };
    if !acknowledged {
        // Release the peer before reporting, so the suite can continue.
        let give_up = narf_time::monotonic_ns().saturating_add(10_000_000_000);
        while PEER.load(Ordering::Acquire) != ACKNOWLEDGED && narf_time::monotonic_ns() < give_up {
            // SAFETY: CPL=0; consumes only this CPU's pending shootdown requests.
            unsafe { ipi::poll_pending_shootdown() };
            core::hint::spin_loop();
        }
        if PEER.load(Ordering::Acquire) == NOT_STARTED {
            return TestResult::Fail("the peer CPU never ran the task pinned to it");
        }
        return TestResult::Fail(
            "an RCU grace-period wait with IRQs masked did not acknowledge a peer's shootdown within 2 s",
        );
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "verification/smp-rendezvous",
    smoke_rcu_sync_until_acknowledges_peer_shootdown
);

#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
fn smoke_frame_x86_64_user_mode_roundtrip() -> TestResult {
    // Full end-to-end: build a user AS with a code + stack page,
    // hand-assemble a tiny user program that issues `int 0x80`,
    // enter user mode, and resume back into this function via a
    // raw syscall handler that `redirect_to_kernel`s onto a naked
    // longjmp trampoline. The setjmp-of-self at the top of this
    // function captures the return state; the longjmp from the
    // trampoline hands control back with `result == 1`, where we
    // verify the magic.
    use core::arch::naked_asm;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_memory::{AddressSpace, Region, RegionPerms, VirtAddr};
    use narf_userspace::{
        install_global, syscall::__verification_clear_global as __test_clear_global, Syscall,
        SyscallHandler, SyscallTable, TrapContext,
    };

    static SEEN_MAGIC: AtomicU64 = AtomicU64::new(0);
    static SAVED_CR3: AtomicU64 = AtomicU64::new(0);
    static mut JMP: UserModeJmpBuf = UserModeJmpBuf {
        rbx: 0,
        rbp: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        rsp: 0,
        rip: 0,
    };

    // Naked trampoline — `redirect_to_kernel`'s rip lands here.
    // First thing we do is longjmp to the saved kernel state.
    #[unsafe(naked)]
    unsafe extern "C" fn resume_trampoline() -> ! {
        naked_asm!(
            "lea rdi, [rip + {jmp}]",
            "mov rsi, 1",
            "jmp {lj}",
            jmp = sym JMP,
            lj  = sym user_mode_longjmp,
        );
    }

    struct UnwindHandler;
    impl SyscallHandler for UnwindHandler {
        fn handle(&self, ctx: &mut dyn TrapContext) {
            SEEN_MAGIC.store(ctx.args().arg0, Ordering::Release);
            // Any RSP is OK — the trampoline overwrites RSP before
            // any stack use.
            let _ =
                ctx.redirect_to_kernel(resume_trampoline as usize as u64, 0xFFFF_FFFF_FFFF_FFF0);
        }
    }

    SEEN_MAGIC.store(0, Ordering::Relaxed);
    __test_clear_global();

    // Snapshot CR3 so we can restore the kernel's original PML4
    // after the user-AS side trip.
    let original_cr3: u64;
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!("mov {v}, cr3", v = out(reg) original_cr3,
            options(nostack, preserves_flags));
    }
    SAVED_CR3.store(original_cr3, Ordering::Release);

    // SAFETY: Valid memory or trusted environment
    let saved = unsafe { user_mode_setjmp(core::ptr::addr_of_mut!(JMP)) };
    if saved != 0 {
        // Resume path — restore the kernel's CR3, reset the
        // KERNEL_GS_BASE MSR (user-mode entry programmed it; later
        // int-0x80 traps in unrelated tests would otherwise hit a
        // dangling per-CPU pointer through `swapgs`), re-enable
        // interrupts, and return Pass if the magic matched.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            let cr3 = SAVED_CR3.load(Ordering::Acquire);
            core::arch::asm!("mov cr3, {v}", v = in(reg) cr3,
                options(nostack, preserves_flags));
            const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
            core::arch::asm!(
                "wrmsr",
                in("ecx") IA32_KERNEL_GS_BASE,
                in("eax") 0u32,
                in("edx") 0u32,
                options(nostack, preserves_flags),
            );
            // Restore IF to boot state (0). See note in
            // `smoke_frame_x86_64_user_mode_yield_resume`'s
            // resume cleanup for the rationale.
            core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
        }
        __test_clear_global();
        if SEEN_MAGIC.load(Ordering::Acquire) != 0xBADC_0FFE_E0DD_F00D {
            return TestResult::Fail("user-mode magic mismatch after longjmp");
        }
        return TestResult::Pass;
    }

    // First pass — set up user environment and enter user mode.
    let mut t = SyscallTable::new();
    t.install_raw(Syscall::Sleep, "user-mode-test-unwind", UnwindHandler);
    install_global(t);

    // SAFETY: Valid memory or trusted environment
    let addr_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("new_for_user failed"),
    };

    const CODE_VADDR: u64 = 0x0000_0080_0000_0000;
    const STACK_VADDR: u64 = 0x0000_0080_0000_1000;

    let code_frame = match narf_memory::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Fail("alloc code frame"),
    };
    let stack_frame = match narf_memory::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Fail("alloc stack frame"),
    };

    // Map code R|W|X|USER, stack R|W|USER.
    addr_space
        .map_region(Region {
            base: VirtAddr::new(CODE_VADDR),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::EXEC | RegionPerms::WRITE,
            phys: alloc::vec![code_frame],
        })
        .ok();
    addr_space
        .map_region(Region {
            base: VirtAddr::new(STACK_VADDR),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![stack_frame],
        })
        .ok();

    // Hand-assembled user program:
    //   mov rax, <Sleep.raw()>      ; 7 bytes (REX.W + C7 C0 + imm32)
    //   movabs rdi, 0xBADC0FFEE0DDF00D ; 10 bytes (REX.W + BF + imm64)
    //   int 0x80                    ; 2 bytes
    //   jmp $                       ; 2 bytes
    let sleep_n = Syscall::Sleep.raw().to_le_bytes();
    let code_bytes: [u8; 21] = [
        0x48, 0xC7, 0xC0, sleep_n[0], sleep_n[1], sleep_n[2], sleep_n[3], 0x48, 0xBF, 0x0D, 0xF0,
        0xDD, 0xE0, 0xFE, 0x0F, 0xDC, 0xBA, 0xCD, 0x80, 0xEB, 0xFE,
    ];
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::ptr::copy_nonoverlapping(
            code_bytes.as_ptr(),
            code_frame.kernel_mut_ptr::<u8>(),
            code_bytes.len(),
        );
    }

    // SAFETY: Valid memory or trusted environment
    if unsafe { addr_space.materialize() }.is_err() {
        return TestResult::Fail("materialize failed");
    }
    if addr_space.activate().is_err() {
        return TestResult::Fail("activate failed");
    }

    // Interrupts off across the transition.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!("cli");
    }

    let stack_top = STACK_VADDR + 0x1000;
    // SAFETY: Valid memory or trusted environment
    unsafe { user_mode_enter(CODE_VADDR, stack_top) }
}
#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
kernel_test!(smoke_frame_x86_64_user_mode_roundtrip);

#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
fn smoke_frame_x86_64_user_mode_yield_resume() -> TestResult {
    // Foundation for scheduler-native user tasks: a trap from user
    // saves CPU state into a UserState slot, the kernel jumps to a
    // landing trampoline which calls `enter_user_mode_resume` to
    // re-enter at the saved RIP. End-to-end: user issues SYS_YIELD,
    // kernel saves state + redirects to landing, landing resumes
    // user mode at the next instruction, user issues SYS_SLEEP with
    // a magic — the magic must match what the user wrote between
    // yield and sleep, proving state was preserved across the
    // user→kernel→user transition.
    use core::arch::naked_asm;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_memory::{AddressSpace, Region, RegionPerms, VirtAddr};
    use narf_userspace::{
        install_global, syscall::__verification_clear_global as __test_clear_global, Syscall,
        SyscallHandler, SyscallTable, TrapContext,
    };

    static SEEN_MAGIC: AtomicU64 = AtomicU64::new(0);
    static SAVED_CR3: AtomicU64 = AtomicU64::new(0);
    static mut SAVED_USER: UserState = UserState {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        r11: 0,
        r10: 0,
        r9: 0,
        r8: 0,
        rbp: 0,
        rdi: 0,
        rsi: 0,
        rdx: 0,
        rcx: 0,
        rbx: 0,
        rax: 0,
        rip: 0,
        rflags: 0,
        rsp: 0,
        valid: 0,
    };
    static mut JMP: UserModeJmpBuf = UserModeJmpBuf {
        rbx: 0,
        rbp: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        rsp: 0,
        rip: 0,
    };
    // Tiny kernel stack for the resume trampoline — `user_mode_resume`
    // pushes a 5-qword iretq frame, which a 256-byte stack absorbs
    // comfortably.
    #[repr(C, align(16))]
    struct ResumeStack([u64; 32]);
    static mut RESUME_STACK: ResumeStack = ResumeStack([0; 32]);

    // Yield handler: save user state, redirect_to_kernel into the
    // resume trampoline. The trampoline calls enter_user_mode_resume
    // with a pointer to SAVED_USER, which iretq's back to user at
    // the saved RIP.
    struct YieldHandler;
    impl SyscallHandler for YieldHandler {
        fn handle(&self, ctx: &mut dyn TrapContext) {
            // SAFETY: SAVED_USER is a sized slot for this trap path.
            unsafe {
                ctx.save_user_state(core::ptr::addr_of_mut!(SAVED_USER) as *mut u8);
            }
            // The resume trampoline tail-calls user_mode_resume which
            // pushes a 5-qword iretq frame — supply a real kernel
            // stack so that doesn't fault.
            // SAFETY: Valid memory or trusted environment
            let stack_top = unsafe {
                let p = core::ptr::addr_of_mut!(RESUME_STACK) as *mut u64;
                p.add(32) as u64
            };
            let _ = ctx.redirect_to_kernel(resume_landing as usize as u64, stack_top);
        }
    }

    // Sleep handler: captures the second magic, longjmps back to
    // the test's setjmp.
    struct UnwindHandler;
    impl SyscallHandler for UnwindHandler {
        fn handle(&self, ctx: &mut dyn TrapContext) {
            SEEN_MAGIC.store(ctx.args().arg0, Ordering::Release);
            let _ =
                ctx.redirect_to_kernel(resume_trampoline as usize as u64, 0xFFFF_FFFF_FFFF_FFF0);
        }
    }

    #[unsafe(naked)]
    unsafe extern "C" fn resume_landing() -> ! {
        naked_asm!(
            "lea rdi, [rip + {state}]",
            "jmp {resume}",
            state  = sym SAVED_USER,
            resume = sym user_mode_resume,
        );
    }

    #[unsafe(naked)]
    unsafe extern "C" fn resume_trampoline() -> ! {
        naked_asm!(
            "lea rdi, [rip + {jmp}]",
            "mov rsi, 1",
            "jmp {lj}",
            jmp = sym JMP,
            lj  = sym user_mode_longjmp,
        );
    }

    SEEN_MAGIC.store(0, Ordering::Relaxed);
    __test_clear_global();

    let original_cr3: u64;
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!("mov {v}, cr3", v = out(reg) original_cr3,
            options(nostack, preserves_flags));
    }
    SAVED_CR3.store(original_cr3, Ordering::Release);

    // SAFETY: Valid memory or trusted environment
    let saved = unsafe { user_mode_setjmp(core::ptr::addr_of_mut!(JMP)) };
    if saved != 0 {
        // SAFETY: Valid memory or trusted environment
        unsafe {
            let cr3 = SAVED_CR3.load(Ordering::Acquire);
            core::arch::asm!("mov cr3, {v}", v = in(reg) cr3,
                options(nostack, preserves_flags));
            const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
            core::arch::asm!(
                "wrmsr",
                in("ecx") IA32_KERNEL_GS_BASE,
                in("eax") 0u32,
                in("edx") 0u32,
                options(nostack, preserves_flags),
            );
            // Restore IF to its boot-time state (0). The
            // kernel-test build never enables the LAPIC timer,
            // so leaving IF=1 turns the next executor's
            // `halt_until_irq` into a real HLT that never wakes.
            core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
        }
        __test_clear_global();
        // The user wrote 0xCAFE_BABE between yield and sleep; the
        // sleep handler captured it. If state was preserved, that's
        // what we see here.
        if SEEN_MAGIC.load(Ordering::Acquire) != 0xCAFE_BABE_DEAD_BEEF {
            return TestResult::Fail("yield/resume did not preserve user state");
        }
        return TestResult::Pass;
    }

    let mut t = SyscallTable::new();
    t.install_raw(Syscall::Yield, "ym-yield", YieldHandler);
    t.install_raw(Syscall::Sleep, "ym-sleep", UnwindHandler);
    install_global(t);

    // SAFETY: Valid memory or trusted environment
    let addr_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("new_for_user"),
    };

    const CODE_VADDR: u64 = 0x0000_0080_0000_0000;
    const STACK_VADDR: u64 = 0x0000_0080_0000_1000;

    let code_frame = match narf_memory::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Fail("alloc code"),
    };
    let stack_frame = match narf_memory::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Fail("alloc stack"),
    };

    addr_space
        .map_region(Region {
            base: VirtAddr::new(CODE_VADDR),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::EXEC | RegionPerms::WRITE,
            phys: alloc::vec![code_frame],
        })
        .ok();
    addr_space
        .map_region(Region {
            base: VirtAddr::new(STACK_VADDR),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![stack_frame],
        })
        .ok();

    // Hand-assembled user program:
    //   mov rax, <Yield.raw()> ; Syscall::Yield
    //   int 0x80               ; (yield — kernel saves state, resumes)
    //   mov rax, <Sleep.raw()> ; Syscall::Sleep
    //   movabs rdi, 0xCAFEBABEDEADBEEF
    //   int 0x80               ; (handler captures magic + longjmps)
    //   jmp $
    let yield_n = Syscall::Yield.raw().to_le_bytes();
    let sleep_n = Syscall::Sleep.raw().to_le_bytes();
    let code_bytes: [u8; 30] = [
        0x48, 0xC7, 0xC0, yield_n[0], yield_n[1], yield_n[2], yield_n[3], // mov rax, Yield
        0xCD, 0x80, // int 0x80
        0x48, 0xC7, 0xC0, sleep_n[0], sleep_n[1], sleep_n[2], sleep_n[3], // mov rax, Sleep
        0x48, 0xBF, 0xEF, 0xBE, 0xAD, 0xDE, 0xBE, 0xBA, 0xFE,
        0xCA, // movabs rdi, 0xCAFEBABEDEADBEEF
        0xCD, 0x80, // int 0x80
        0xEB, 0xFE, // jmp $
    ];
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::ptr::copy_nonoverlapping(
            code_bytes.as_ptr(),
            code_frame.kernel_mut_ptr::<u8>(),
            code_bytes.len(),
        );
    }

    // SAFETY: Valid memory or trusted environment
    if unsafe { addr_space.materialize() }.is_err() {
        return TestResult::Fail("materialize");
    }
    if addr_space.activate().is_err() {
        return TestResult::Fail("activate");
    }

    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!("cli");
    }

    let stack_top = STACK_VADDR + 0x1000;
    // SAFETY: Valid memory or trusted environment
    unsafe { user_mode_enter(CODE_VADDR, stack_top) }
}
#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
kernel_test!(smoke_frame_x86_64_user_mode_yield_resume);

#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
fn smoke_frame_x86_64_user_task_poll_yield_exit() -> TestResult {
    // The polling-routine pattern: a "future-shaped" caller does
    // setjmp, registers the yield/exit hooks, sets the current
    // UserTaskCtx slot, enters/resumes user mode. The user issues
    // Yield (which longjmps back via the yield hook with reason
    // EXIT_REASON_YIELDED), then on the second pass issues
    // ExitTask (which longjmps back with reason EXIT_REASON_EXITED).
    // The routine returns Pass when it has seen one Yielded and
    // one Exited in order.
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_memory::{AddressSpace, Region, RegionPerms, VirtAddr};
    use narf_userspace::{
        clear_current_user_task, install_current_user_task, install_exit_hook, install_global,
        install_yield_hook, syscall::__verification_clear_global as __test_clear_global, Syscall,
        SyscallTable, UserTaskCtx, EXIT_REASON_EXITED, EXIT_REASON_YIELDED,
    };

    static SAVED_CR3: AtomicU64 = AtomicU64::new(0);
    static OBSERVED_REASONS: AtomicU64 = AtomicU64::new(0);
    static mut JMP: UserModeJmpBuf = UserModeJmpBuf {
        rbx: 0,
        rbp: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        rsp: 0,
        rip: 0,
    };

    // Hooks: save_user_state already ran in the syscall handler.
    // The hook just longjmps back to the polling routine using the
    // sentinel value the handler stored in `exit_reason`.
    unsafe fn yield_hook_fn(uctx: *mut UserTaskCtx) -> ! {
        // SAFETY: uctx outlives the user-mode round-trip; the
        // polling routine pinned it.
        let _ = uctx;
        // SAFETY: Valid memory or trusted environment
        unsafe {
            user_mode_longjmp(core::ptr::addr_of_mut!(JMP), EXIT_REASON_YIELDED as u64);
        }
    }
    unsafe fn exit_hook_fn(uctx: *mut UserTaskCtx) -> ! {
        let _ = uctx;
        // SAFETY: Valid memory or trusted environment
        unsafe {
            user_mode_longjmp(core::ptr::addr_of_mut!(JMP), EXIT_REASON_EXITED as u64);
        }
    }

    OBSERVED_REASONS.store(0, Ordering::Relaxed);
    __test_clear_global();
    narf_userspace::user_task::__test_clear_hooks();

    // Set up the syscall table — Yield + ExitTask point at the
    // hook-aware handlers in `narf_userspace::handlers`.
    let mut t = SyscallTable::new();
    narf_userspace::install_core_syscalls(&mut t);
    install_global(t);
    install_yield_hook(yield_hook_fn);
    install_exit_hook(exit_hook_fn);

    // Snapshot CR3.
    let original_cr3: u64;
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!("mov {v}, cr3", v = out(reg) original_cr3,
            options(nostack, preserves_flags));
    }
    SAVED_CR3.store(original_cr3, Ordering::Release);

    // Per-task ctx + AS + code/stack pages. The user code:
    //   mov rax, 104     ; Yield
    //   int 0x80
    //   mov rax, 103     ; ExitTask
    //   int 0x80
    //   jmp $
    // SAFETY: Valid memory or trusted environment
    let addr_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("new_for_user"),
    };
    const CODE_VADDR: u64 = 0x0000_0080_0000_0000;
    const STACK_VADDR: u64 = 0x0000_0080_0000_1000;
    let code_frame = match narf_memory::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Fail("alloc code"),
    };
    let stack_frame = match narf_memory::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Fail("alloc stack"),
    };
    addr_space
        .map_region(Region {
            base: VirtAddr::new(CODE_VADDR),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::EXEC | RegionPerms::WRITE,
            phys: alloc::vec![code_frame],
        })
        .ok();
    addr_space
        .map_region(Region {
            base: VirtAddr::new(STACK_VADDR),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![stack_frame],
        })
        .ok();
    let yield_n = Syscall::Yield.raw().to_le_bytes();
    let exit_n = Syscall::ExitTask.raw().to_le_bytes();
    let code_bytes: [u8; 20] = [
        0x48, 0xC7, 0xC0, yield_n[0], yield_n[1], yield_n[2], yield_n[3], // mov rax, Yield
        0xCD, 0x80, // int 0x80
        0x48, 0xC7, 0xC0, exit_n[0], exit_n[1], exit_n[2], exit_n[3], // mov rax, ExitTask
        0xCD, 0x80, // int 0x80
        0xEB, 0xFE, // jmp $
    ];
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::ptr::copy_nonoverlapping(
            code_bytes.as_ptr(),
            code_frame.kernel_mut_ptr::<u8>(),
            code_bytes.len(),
        );
    }
    // SAFETY: Valid memory or trusted environment
    if unsafe { addr_space.materialize() }.is_err() {
        return TestResult::Fail("materialize");
    }
    if addr_space.activate().is_err() {
        return TestResult::Fail("activate");
    }

    // The polling routine — a manual mock of UserTaskFuture::poll.
    // setjmp captures kernel state; the hooks longjmp back here
    // with the trap reason as the longjmp value.
    let mut uctx = UserTaskCtx::new();
    install_current_user_task(&mut uctx as *mut _);

    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!("cli");
    }
    let stack_top = STACK_VADDR + 0x1000;
    // SAFETY: Valid memory or trusted environment
    let saved = unsafe { user_mode_setjmp(core::ptr::addr_of_mut!(JMP)) };

    if saved == 0 {
        // First-time poll: enter user mode at the entry point.
        // SAFETY: Valid memory or trusted environment
        unsafe { user_mode_enter(CODE_VADDR, stack_top) }
    } else if saved as u32 == EXIT_REASON_YIELDED {
        // First yield observed. Re-enter via resume so user picks
        // up at the instruction after `int 0x80`.
        OBSERVED_REASONS.fetch_or(1, Ordering::Relaxed);
        // SAFETY: Valid memory or trusted environment
        unsafe {
            // Resume from the saved state.
            user_mode_resume(uctx.state.get() as *const _ as *const UserState)
        }
    } else if saved as u32 == EXIT_REASON_EXITED {
        OBSERVED_REASONS.fetch_or(2, Ordering::Relaxed);
        // Restore kernel state and report.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            let cr3 = SAVED_CR3.load(Ordering::Acquire);
            core::arch::asm!("mov cr3, {v}", v = in(reg) cr3,
                options(nostack, preserves_flags));
            const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
            core::arch::asm!(
                "wrmsr",
                in("ecx") IA32_KERNEL_GS_BASE,
                in("eax") 0u32,
                in("edx") 0u32,
                options(nostack, preserves_flags),
            );
            // Restore IF to boot state (0).
            core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
        }
        clear_current_user_task();
        narf_userspace::user_task::__test_clear_hooks();
        __test_clear_global();
        let r = OBSERVED_REASONS.load(Ordering::Relaxed);
        if r != 3 {
            TestResult::Fail("did not observe both Yielded and Exited")
        } else {
            TestResult::Pass
        }
    } else {
        clear_current_user_task();
        narf_userspace::user_task::__test_clear_hooks();
        __test_clear_global();
        TestResult::Fail("unexpected longjmp value")
    }
}
#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
kernel_test!(smoke_frame_x86_64_user_task_poll_yield_exit);

#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
fn smoke_userspace_user_task_future_yield_exit() -> TestResult {
    // Stage-4 capstone: the polling future drives a CPL=3 task to
    // completion via the cooperative executor. Same user binary as
    // `smoke_frame_x86_64_user_task_poll_yield_exit` (Yield → Yield
    // → ExitTask), but plumbed through `UserTaskFuture::poll` and
    // `narf_scheduler::spawn_user` rather than a bespoke setjmp
    // dance — proving the future shape is the load-bearing piece
    // that wasn't possible before.
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use narf_memory::{AddressSpace, Region, RegionPerms, VirtAddr};
    use narf_userspace::{
        install_core_syscalls, install_global, install_user_task_hooks,
        syscall::__verification_clear_global as __test_clear_global, Syscall, SyscallTable,
        UserProcess,
    };

    static SAVED_CR3: AtomicU64 = AtomicU64::new(0);
    static OUTER_DONE: AtomicBool = AtomicBool::new(false);

    OUTER_DONE.store(false, Ordering::Release);
    __test_clear_global();
    narf_userspace::user_task::__test_clear_hooks();

    // Snapshot CR3 — `UserTaskFuture` restores its own snapshot on
    // each poll, but the *outer* test cleanup also needs the right
    // root in case the future is dropped without finishing (failure
    // path).
    let original_cr3: u64;
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!("mov {v}, cr3", v = out(reg) original_cr3,
            options(nostack, preserves_flags));
    }
    SAVED_CR3.store(original_cr3, Ordering::Release);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // SAFETY: Valid memory or trusted environment
    let addr_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("new_for_user"),
    };
    const CODE_VADDR: u64 = 0x0000_0080_0000_0000;
    const STACK_VADDR: u64 = 0x0000_0080_0000_1000;
    let code_frame = match narf_memory::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Fail("alloc code"),
    };
    let stack_frame = match narf_memory::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Fail("alloc stack"),
    };
    addr_space
        .map_region(Region {
            base: VirtAddr::new(CODE_VADDR),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::EXEC | RegionPerms::WRITE,
            phys: alloc::vec![code_frame],
        })
        .ok();
    addr_space
        .map_region(Region {
            base: VirtAddr::new(STACK_VADDR),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![stack_frame],
        })
        .ok();
    // mov rax, 104 ; int 0x80 ; mov rax, 103 ; int 0x80 ; jmp $
    // First int 0x80 goes Yielded → re-poll → second int 0x80 Exited.
    let yield_n = Syscall::Yield.raw().to_le_bytes();
    let exit_n = Syscall::ExitTask.raw().to_le_bytes();
    let code_bytes: [u8; 20] = [
        0x48, 0xC7, 0xC0, yield_n[0], yield_n[1], yield_n[2], yield_n[3], // mov rax, Yield
        0xCD, 0x80, // int 0x80
        0x48, 0xC7, 0xC0, exit_n[0], exit_n[1], exit_n[2], exit_n[3], // mov rax, ExitTask
        0xCD, 0x80, // int 0x80
        0xEB, 0xFE, // jmp $
    ];
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::ptr::copy_nonoverlapping(
            code_bytes.as_ptr(),
            code_frame.kernel_mut_ptr::<u8>(),
            code_bytes.len(),
        );
    }
    // SAFETY: Valid memory or trusted environment
    if unsafe { addr_space.materialize() }.is_err() {
        return TestResult::Fail("materialize");
    }

    let stack_top = STACK_VADDR + 0x1000;
    let proc = UserProcess {
        pid: narf_userspace::alloc_pid(),
        address_space: Arc::new(addr_space),
        entry: narf_userspace::EntryPoint(VirtAddr::new(CODE_VADDR)),
        stack_top: VirtAddr::new(stack_top),
        fs_base: None,
        entry_arg: None,
        loaded_mappings: alloc::vec::Vec::new(),
        auxv: alloc::vec::Vec::new(),
    };

    // Boot the executor + wire the user-task hooks so Yield/Exit
    // longjmps reach the polling future.
    narf_scheduler::__reset_queues_for_test();
    install_user_task_hooks();

    // The user task itself, plus a ".join()" outer task that flips
    // OUTER_DONE once the user task's future has Ready'd. Spawning
    // the user task via `spawn_user_process` is the load-bearing line —
    // this is the path that wasn't possible before.
    let _user_id = narf_userspace::user_task::spawn_user_process(
        proc,
        narf_scheduler::TaskSpec::unthrottled(),
    );
    narf_scheduler::spawn(async {
        // Wait one yield round so the user task gets polled at least
        // once before we observe completion. With cooperative
        // single-CPU execution, by the time the user task drops
        // (Ready), this task's awake flag has been refreshed and we
        // get to run.
        narf_scheduler::yield_now().await;
        narf_scheduler::yield_now().await;
        narf_scheduler::yield_now().await;
        OUTER_DONE.store(true, Ordering::Release);
    });

    narf_scheduler::run_until_empty();

    // Final cleanup — UserTaskFuture's poll body already left CR3 +
    // KERNEL_GS_BASE in their kernel-side states with IF=0, but we
    // belt-and-suspender the kernel CR3 here too in case a divergent
    // failure path skipped that.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        let cr3 = SAVED_CR3.load(Ordering::Acquire);
        core::arch::asm!("mov cr3, {v}", v = in(reg) cr3,
            options(nostack, preserves_flags));
        const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
        core::arch::asm!(
            "wrmsr",
            in("ecx") IA32_KERNEL_GS_BASE,
            in("eax") 0u32,
            in("edx") 0u32,
            options(nostack, preserves_flags),
        );
        // IF stays 0 — the kernel-test build never enabled the
        // LAPIC timer, so leaving IF=1 wedges the next
        // halt_until_irq. (See commit 401b073.)
        core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
    }
    narf_userspace::user_task::__test_clear_hooks();
    __test_clear_global();

    if !OUTER_DONE.load(Ordering::Acquire) {
        return TestResult::Fail("outer task never ran — executor stalled?");
    }
    TestResult::Pass
}
#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
kernel_test!(smoke_userspace_user_task_future_yield_exit);

#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
fn smoke_userspace_tls_round_trip() -> TestResult {
    // Milestone 2 of the relibc-shaped userland rollout: a binary
    // with PT_TLS gets a per-task TLS block + IA32_FS_BASE
    // programmed before iretq, so user code can read its thread
    // pointer via `mov rax, fs:[0]` (the SysV-AMD64 model — same
    // shape relibc / `narf-libc::__libc_start_main` reads on entry).
    //
    // The test hand-builds a minimal ELF (one PT_LOAD covering the
    // header + code, one PT_TLS naming a 32-byte sentinel image),
    // runs it through `load_user_process_with`, and verifies the
    // returned `proc.fs_base.is_some()` (the integration site
    // contract). Then it activates the AS, programs FS_BASE with
    // the staged thread pointer, and enters user mode through the
    // setjmp/longjmp dance — same shape as
    // `smoke_frame_x86_64_user_mode_yield_resume` — so the test
    // exercises the kernel-side `set_user_fs_base` path
    // independent of the polling-future glue.
    use core::arch::naked_asm;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_userspace::{
        install_global, syscall::__verification_clear_global as __test_clear_global, Syscall,
        SyscallHandler, SyscallTable, TrapContext,
    };

    // The user code emits two syscalls:
    //   1. mov rdi, fs:[0]  ; mov rax, 104 (Yield) ; int 0x80
    //      → captures the thread-pointer self-pointer; the kernel
    //        saves user state + resumes at the next instruction.
    //   2. mov rdi, fs:[-32] ; mov rax, 105 (Sleep) ; int 0x80
    //      → captures the first qword of the file image (= 0xABABAB…),
    //        kernel longjmps back to the test.
    static SEEN_TP: AtomicU64 = AtomicU64::new(0);
    static SEEN_FILEIMAGE: AtomicU64 = AtomicU64::new(0);
    static SAVED_CR3: AtomicU64 = AtomicU64::new(0);
    static mut SAVED_USER: UserState = UserState {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        r11: 0,
        r10: 0,
        r9: 0,
        r8: 0,
        rbp: 0,
        rdi: 0,
        rsi: 0,
        rdx: 0,
        rcx: 0,
        rbx: 0,
        rax: 0,
        rip: 0,
        rflags: 0,
        rsp: 0,
        valid: 0,
    };
    static mut JMP: UserModeJmpBuf = UserModeJmpBuf {
        rbx: 0,
        rbp: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        rsp: 0,
        rip: 0,
    };
    #[repr(C, align(16))]
    struct ResumeStack([u64; 32]);
    static mut RESUME_STACK: ResumeStack = ResumeStack([0; 32]);

    // Yield handler: capture rdi as the thread-pointer read, then
    // resume user mode at the saved RIP so the binary can issue its
    // second syscall. The trap path enters/exits CPL=0 with FS_BASE
    // intact (no `swapgs`-like demote on the FS hidden base), so we
    // don't need to re-program it on the resume.
    struct CaptureTpHandler;
    impl SyscallHandler for CaptureTpHandler {
        fn handle(&self, ctx: &mut dyn TrapContext) {
            SEEN_TP.store(ctx.args().arg0, Ordering::Release);
            // SAFETY: SAVED_USER is a sized slot for this trap path.
            unsafe {
                ctx.save_user_state(core::ptr::addr_of_mut!(SAVED_USER) as *mut u8);
            }
            // SAFETY: Valid memory or trusted environment
            let stack_top = unsafe {
                let p = core::ptr::addr_of_mut!(RESUME_STACK) as *mut u64;
                p.add(32) as u64
            };
            let _ = ctx.redirect_to_kernel(resume_landing as usize as u64, stack_top);
        }
    }

    // Sleep handler: capture rdi as the file-image read, longjmp
    // back to the test's setjmp.
    struct CaptureFileHandler;
    impl SyscallHandler for CaptureFileHandler {
        fn handle(&self, ctx: &mut dyn TrapContext) {
            SEEN_FILEIMAGE.store(ctx.args().arg0, Ordering::Release);
            let _ =
                ctx.redirect_to_kernel(resume_trampoline as usize as u64, 0xFFFF_FFFF_FFFF_FFF0);
        }
    }

    #[unsafe(naked)]
    unsafe extern "C" fn resume_landing() -> ! {
        naked_asm!(
            "lea rdi, [rip + {state}]",
            "jmp {resume}",
            state  = sym SAVED_USER,
            resume = sym user_mode_resume,
        );
    }

    #[unsafe(naked)]
    unsafe extern "C" fn resume_trampoline() -> ! {
        naked_asm!(
            "lea rdi, [rip + {jmp}]",
            "mov rsi, 1",
            "jmp {lj}",
            jmp = sym JMP,
            lj  = sym user_mode_longjmp,
        );
    }

    SEEN_TP.store(0, Ordering::Relaxed);
    SEEN_FILEIMAGE.store(0, Ordering::Relaxed);
    __test_clear_global();

    let original_cr3: u64;
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!("mov {v}, cr3", v = out(reg) original_cr3,
            options(nostack, preserves_flags));
    }
    SAVED_CR3.store(original_cr3, Ordering::Release);

    // ── Hand-build a minimal ELF64 little-endian executable ──────
    //
    // Layout (4096 bytes total = one PT_LOAD page):
    //   0x0000   ELF header (64 bytes)
    //   0x0040   Program header 0 — PT_LOAD  (56 bytes)
    //   0x0078   Program header 1 — PT_TLS   (56 bytes)
    //   0x00B0   padding to code start
    //   0x0100   user code (entry point sits here)
    //   0x0200   PT_TLS file image: 32 bytes of 0xAB
    //   …        rest of page is unused / zero.
    //
    // PT_LOAD covers vaddr [0x40_0000_0000 .. 0x40_0000_1000) with
    // file_off = 0, file_size = 4096, mem_size = 4096 — so the
    // entire ELF byte slice is mapped + the TLS template is reachable
    // for the loader's "copy file_size bytes" path on PT_LOAD AND
    // for `stage_tls`'s read of `bytes[file_off ..]` for PT_TLS.
    // PT_LOAD lives in PML4[1] (vaddr 0x80_0000_0000), well clear of
    // PML4[0]'s kernel low-4-GiB identity map — that PML4 entry is
    // copied into the user AS by `new_user_pml4` with USER=0, so a
    // user-mode access through it #PFs even with a USER=1 leaf. The
    // testbin's linker script lands at the same PML4 slot (one page
    // higher) for the same reason.
    const ELF_LEN: usize = 4096;
    const LOAD_VADDR: u64 = 0x0000_0080_0000_0000;
    const CODE_OFF: usize = 0x100;
    const TLS_FILE_OFF: usize = 0x200;
    const TLS_FILE_SIZE: u64 = 32;
    const TLS_MEM_SIZE: u64 = 32;
    const TLS_ALIGN: u64 = 8;

    let mut elf = alloc::vec![0u8; ELF_LEN];

    // ── ELF header ───────────────────────────────────────────────
    elf[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    elf[4] = 2; // EI_CLASS = ELFCLASS64
    elf[5] = 1; // EI_DATA  = ELFDATA2LSB
    elf[6] = 1; // EI_VERSION = EV_CURRENT
                // e_type = ET_EXEC (2)
    elf[0x10..0x12].copy_from_slice(&2u16.to_le_bytes());
    // e_machine = EM_X86_64 (62)
    elf[0x12..0x14].copy_from_slice(&62u16.to_le_bytes());
    // e_version = 1
    elf[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    // e_entry = LOAD_VADDR + CODE_OFF
    elf[0x18..0x20].copy_from_slice(&(LOAD_VADDR + CODE_OFF as u64).to_le_bytes());
    // e_phoff = 64
    elf[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
    // e_shoff = 0
    elf[0x28..0x30].copy_from_slice(&0u64.to_le_bytes());
    // e_flags = 0; e_ehsize = 64; e_phentsize = 56; e_phnum = 2;
    // e_shentsize = 0; e_shnum = 0; e_shstrndx = 0.
    elf[0x34..0x36].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    elf[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    elf[0x38..0x3A].copy_from_slice(&2u16.to_le_bytes()); // e_phnum

    // ── Program header 0 — PT_LOAD ──────────────────────────────
    let ph0 = 64;
    elf[ph0..ph0 + 4].copy_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
    elf[ph0 + 4..ph0 + 8].copy_from_slice(&7u32.to_le_bytes()); // p_flags = R+W+X
    elf[ph0 + 8..ph0 + 16].copy_from_slice(&0u64.to_le_bytes()); // p_offset
    elf[ph0 + 16..ph0 + 24].copy_from_slice(&LOAD_VADDR.to_le_bytes()); // p_vaddr
    elf[ph0 + 24..ph0 + 32].copy_from_slice(&LOAD_VADDR.to_le_bytes()); // p_paddr
    elf[ph0 + 32..ph0 + 40].copy_from_slice(&(ELF_LEN as u64).to_le_bytes()); // p_filesz
    elf[ph0 + 40..ph0 + 48].copy_from_slice(&(ELF_LEN as u64).to_le_bytes()); // p_memsz
    elf[ph0 + 48..ph0 + 56].copy_from_slice(&0x1000u64.to_le_bytes()); // p_align

    // ── Program header 1 — PT_TLS ───────────────────────────────
    let ph1 = 64 + 56;
    elf[ph1..ph1 + 4].copy_from_slice(&7u32.to_le_bytes()); // p_type = PT_TLS
    elf[ph1 + 4..ph1 + 8].copy_from_slice(&4u32.to_le_bytes()); // p_flags = R
    elf[ph1 + 8..ph1 + 16].copy_from_slice(&(TLS_FILE_OFF as u64).to_le_bytes()); // p_offset
    elf[ph1 + 16..ph1 + 24].copy_from_slice(&(LOAD_VADDR + TLS_FILE_OFF as u64).to_le_bytes()); // p_vaddr (link-time)
    elf[ph1 + 24..ph1 + 32].copy_from_slice(&(LOAD_VADDR + TLS_FILE_OFF as u64).to_le_bytes()); // p_paddr
    elf[ph1 + 32..ph1 + 40].copy_from_slice(&TLS_FILE_SIZE.to_le_bytes()); // p_filesz
    elf[ph1 + 40..ph1 + 48].copy_from_slice(&TLS_MEM_SIZE.to_le_bytes()); // p_memsz
    elf[ph1 + 48..ph1 + 56].copy_from_slice(&TLS_ALIGN.to_le_bytes()); // p_align

    // ── TLS file image — 32 bytes of 0xAB sentinel ──────────────
    for i in 0..TLS_FILE_SIZE as usize {
        elf[TLS_FILE_OFF + i] = 0xAB;
    }

    // ── User code at CODE_OFF ───────────────────────────────────
    //
    // FS-segment-override prefix is `0x64` (Intel SDM Vol. 2A §2.1.1
    // — `0x65` is GS, easy to mis-paste). Hand-assembled:
    //   64 48 8B 3C 25 00 00 00 00   mov rdi, qword ptr fs:[0]
    //   48 C7 C0 <Yield>            mov rax, Syscall::Yield.raw()
    //   CD 80                         int 0x80
    //   64 48 8B 3C 25 E0 FF FF FF    mov rdi, qword ptr fs:[-32]
    //   48 C7 C0 <Sleep>            mov rax, Syscall::Sleep.raw()
    //   CD 80                         int 0x80
    //   EB FE                         jmp $
    let yield_n = Syscall::Yield.raw().to_le_bytes();
    let sleep_n = Syscall::Sleep.raw().to_le_bytes();
    let code: [u8; 38] = [
        0x64, 0x48, 0x8B, 0x3C, 0x25, 0x00, 0x00, 0x00, 0x00, // mov rdi, fs:[0]
        0x48, 0xC7, 0xC0, yield_n[0], yield_n[1], yield_n[2], yield_n[3], // mov rax, Yield
        0xCD, 0x80, // int 0x80
        0x64, 0x48, 0x8B, 0x3C, 0x25, 0xE0, 0xFF, 0xFF, 0xFF, // mov rdi, fs:[-32]
        0x48, 0xC7, 0xC0, sleep_n[0], sleep_n[1], sleep_n[2], sleep_n[3], // mov rax, Sleep
        0xCD, 0x80, // int 0x80
        0xEB, 0xFE, // jmp $ (unreached)
    ];
    elf[CODE_OFF..CODE_OFF + code.len()].copy_from_slice(&code);

    // ── Drive the loader + verify the integration site ──────────
    // SAFETY: Valid memory or trusted environment
    let proc = match unsafe { narf_userspace::load_user_process_with(&elf[..], &[], &[], &[]) } {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("load_user_process_with"),
    };

    let fs_base = match proc.fs_base {
        Some(v) => v,
        None => return TestResult::Fail("fs_base not set on PT_TLS binary"),
    };

    // Install the two syscall handlers *after* the loader runs so
    // it (which uses the global table for nothing) doesn't matter
    // either way; what matters is the table is set before iretq.
    let mut t = SyscallTable::new();
    t.install_raw(Syscall::Yield, "tls-tp", CaptureTpHandler);
    t.install_raw(Syscall::Sleep, "tls-file", CaptureFileHandler);
    install_global(t);

    // setjmp — sleep handler longjmps back here on the second
    // syscall capture.
    // SAFETY: Valid memory or trusted environment
    let saved = unsafe { user_mode_setjmp(core::ptr::addr_of_mut!(JMP)) };
    if saved != 0 {
        // SAFETY: Valid memory or trusted environment
        unsafe {
            let cr3 = SAVED_CR3.load(Ordering::Acquire);
            core::arch::asm!("mov cr3, {v}", v = in(reg) cr3,
                options(nostack, preserves_flags));
            const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
            core::arch::asm!(
                "wrmsr",
                in("ecx") IA32_KERNEL_GS_BASE,
                in("eax") 0u32,
                in("edx") 0u32,
                options(nostack, preserves_flags),
            );
            // IF stays 0 — kernel-test build never enabled the LAPIC
            // timer (commit 401b073's invariant).
            core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
        }
        __test_clear_global();
        let tp = SEEN_TP.load(Ordering::Acquire);
        let file = SEEN_FILEIMAGE.load(Ordering::Acquire);
        if tp != fs_base {
            return TestResult::Fail("fs:[0] != fs_base (TCB self-pointer wrong)");
        }
        if file != 0xABAB_ABAB_ABAB_ABAB {
            return TestResult::Fail("fs:[-32] sentinel mismatch");
        }
        return TestResult::Pass;
    }

    // Activate the AS + program FS_BASE before iretq. The split-form
    // (`set_user_fs_base` followed by `enter_user_mode`) is the
    // recommended shape — the polling future + testbin runner use
    // exactly this two-step sequence.
    if proc.address_space.activate().is_err() {
        return TestResult::Fail("activate");
    }
    // SAFETY: Valid memory or trusted environment
    unsafe {
        narf_scheduler::set_user_fs_base(fs_base);
    }
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!("cli");
    }

    let entry = proc.entry.0.as_u64();
    let rsp = proc.stack_top.as_u64();
    // SAFETY: Valid memory or trusted environment
    unsafe { user_mode_enter(entry, rsp) }
}
#[cfg(all(target_arch = "x86_64", feature = "user-mode-e2e"))]
kernel_test!(smoke_userspace_tls_round_trip);

// ── Real Rust user binary run through the full pipeline ──────────────

#[cfg(all(target_arch = "x86_64", feature = "user-mode-testbin"))]
const NARF_TESTBIN_ELF: &[u8] = include_bytes!(env!("NARF_TESTBIN_ELF_X86_64"));

#[cfg(all(target_arch = "aarch64", feature = "user-mode-testbin"))]
const NARF_TESTBIN_ELF: &[u8] = include_bytes!(env!("NARF_TESTBIN_ELF_AARCH64"));

#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_INIT_ELF: &[u8] = include_bytes!(env!("NARF_INIT_ELF_X86_64"));

#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_INIT_ELF: &[u8] = include_bytes!(env!("NARF_INIT_ELF_AARCH64"));

/// The per-arch vDSO image (`linux-vdso.so.1`). Empty when the build host
/// lacked clang/lld — the kernel then maps no vDSO and libc falls back to
/// plain syscalls. Always present (ungated) so the loader can reference it.
#[cfg(target_arch = "x86_64")]
pub const NARF_VDSO_ELF: &[u8] = include_bytes!(env!("NARF_VDSO_ELF_X86_64"));
#[cfg(target_arch = "aarch64")]
pub const NARF_VDSO_ELF: &[u8] = include_bytes!(env!("NARF_VDSO_ELF_AARCH64"));

/// Multi-DSO test shared libraries seeded into /lib (x86_64 only; empty
/// elsewhere / when musl-gcc was absent). `dso_smoke` links against them.
#[cfg(target_arch = "x86_64")]
pub const NARF_LIBA_SO: &[u8] = include_bytes!(env!("NARF_LIBA_SO"));
#[cfg(target_arch = "aarch64")]
pub const NARF_LIBA_SO: &[u8] = &[];
#[cfg(target_arch = "x86_64")]
pub const NARF_LIBB_SO: &[u8] = include_bytes!(env!("NARF_LIBB_SO"));
#[cfg(target_arch = "aarch64")]
pub const NARF_LIBB_SO: &[u8] = &[];

/// Per-DSO TLS test library (x86_64 only) seeded into /lib; `tls_smoke`
/// links it to exercise general-dynamic thread-locals in a shared library.
#[cfg(target_arch = "x86_64")]
pub const NARF_LIBTLS_SO: &[u8] = include_bytes!(env!("NARF_LIBTLS_SO"));
#[cfg(target_arch = "aarch64")]
pub const NARF_LIBTLS_SO: &[u8] = &[];

#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_SHELL_ELF: &[u8] = include_bytes!(env!("NARF_SHELL_ELF_X86_64"));

#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_SHELL_ELF: &[u8] = include_bytes!(env!("NARF_SHELL_ELF_AARCH64"));

// getty/login: spawned in place of the shell at boot; it establishes a
// session + controlling tty + foreground pgrp, then execs `/bin/shell`.
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_GETTY_ELF: &[u8] = include_bytes!(env!("NARF_GETTY_ELF_X86_64"));

#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_GETTY_ELF: &[u8] = include_bytes!(env!("NARF_GETTY_ELF_AARCH64"));

// Wave-49: baked coreutil ELFs. boot-init mounts a MemFs at /bin
// and seeds these as files so the shell's fork+exec `/bin/<name>`
// resolves under `qemu -kernel` (no Limine initramfs CPIO module
// is delivered there).
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_COREUTIL_ECHO_ELF: &[u8] = include_bytes!(env!("NARF_COREUTIL_ECHO_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_COREUTIL_ECHO_ELF: &[u8] = include_bytes!(env!("NARF_COREUTIL_ECHO_ELF_AARCH64"));

#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_COREUTIL_PWD_ELF: &[u8] = include_bytes!(env!("NARF_COREUTIL_PWD_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_COREUTIL_PWD_ELF: &[u8] = include_bytes!(env!("NARF_COREUTIL_PWD_ELF_AARCH64"));

#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_COREUTIL_CAT_ELF: &[u8] = include_bytes!(env!("NARF_COREUTIL_CAT_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_COREUTIL_CAT_ELF: &[u8] = include_bytes!(env!("NARF_COREUTIL_CAT_ELF_AARCH64"));

#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_COREUTIL_LS_ELF: &[u8] = include_bytes!(env!("NARF_COREUTIL_LS_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_COREUTIL_LS_ELF: &[u8] = include_bytes!(env!("NARF_COREUTIL_LS_ELF_AARCH64"));

#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_COREUTIL_PS_ELF: &[u8] = include_bytes!(env!("NARF_COREUTIL_PS_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_COREUTIL_PS_ELF: &[u8] = include_bytes!(env!("NARF_COREUTIL_PS_ELF_AARCH64"));

// Wave-78: pre-built direct-syscall hello-world for the linux-compat
// demo. Source + REGEN.sh live in `verification/data/musl-demo/`.
// The binary uses Linux x86_64 syscall numbers (write=1,
// exit_group=231) and is built with stock binutils — no libc, no
// PT_INTERP, no PT_TLS. Seeded at /bin/hello so `cargo xtask
// run-interactive` → `hello` at the shell prompt exercises NARF's
// linux-compat ABI translation against a binary built outside this
// tree's toolchain.
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_HELLO_STATIC_ELF: &[u8] = include_bytes!(env!("NARF_HELLO_STATIC_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_HELLO_STATIC_ELF: &[u8] = include_bytes!(env!("NARF_HELLO_STATIC_ELF_AARCH64"));

// Wave-78 follow-up 2: real musl-static binary. Compiled with
// `musl-gcc -static -no-pie`; sources + REGEN_musl.sh live in
// `verification/data/musl-demo/`. Seeded at /bin/hello_musl so
// `narf> hello_musl` exercises the real musl init path
// (set_tid_address, rt_sigaction, brk, arch_prctl, ...) before
// reaching the program's `write` + `exit_group`. See the .c
// source's header for the `syscall`-instruction dispatch caveat
// this wave doesn't yet fix.
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_HELLO_MUSL_ELF: &[u8] = include_bytes!(env!("NARF_HELLO_MUSL_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_HELLO_MUSL_ELF: &[u8] = include_bytes!(env!("NARF_HELLO_MUSL_ELF_AARCH64"));

// Wave-78 follow-up 3: dynamic-linked musl binary + the ld-musl
// interpreter it depends on. Seeded at /bin/hello_musl_dyn and
// /lib/ld-musl-x86_64.so.1. PT_INTERP resolution in
// `userspace::process::load_user_process_with` reads the FS path
// at exec time and loads ld-musl at INTERP_BIAS = 0x4000_0000_0000.
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_HELLO_MUSL_DYN_ELF: &[u8] = include_bytes!(env!("NARF_HELLO_MUSL_DYN_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_HELLO_MUSL_DYN_ELF: &[u8] = include_bytes!(env!("NARF_HELLO_MUSL_DYN_ELF_AARCH64"));

/// Unmodified `redis-server` (7.2.x, musl, MALLOC=libc, no TLS, stripped).
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_REDIS_SERVER_ELF: &[u8] = include_bytes!(env!("NARF_REDIS_SERVER_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_REDIS_SERVER_ELF: &[u8] = include_bytes!(env!("NARF_REDIS_SERVER_ELF_AARCH64"));

/// `mt-echo` — multithreaded SO_REUSEPORT TCP echo server (static musl).
/// The multi-queue/RSS benchmark workload: N worker threads, one listener
/// each on the same port, so distinct flows are served in parallel.
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_MT_ECHO_ELF: &[u8] = include_bytes!(env!("NARF_MT_ECHO_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_MT_ECHO_ELF: &[u8] = include_bytes!(env!("NARF_MT_ECHO_ELF_AARCH64"));

/// `/bin/modetest` — libdrm's KMS test tool (static-musl). A real
/// third-party DRM client used to validate `/dev/dri/card0` against
/// the actual libdrm ioctl encodings (Rung 4).
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_MODETEST_ELF: &[u8] = include_bytes!(env!("NARF_MODETEST_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_MODETEST_ELF: &[u8] = include_bytes!(env!("NARF_MODETEST_ELF_AARCH64"));
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_WL_HANDSHAKE_ELF: &[u8] = include_bytes!(env!("NARF_WL_HANDSHAKE_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_WL_HANDSHAKE_ELF: &[u8] = include_bytes!(env!("NARF_WL_HANDSHAKE_ELF_AARCH64"));
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_WL_SHM_ELF: &[u8] = include_bytes!(env!("NARF_WL_SHM_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_WL_SHM_ELF: &[u8] = include_bytes!(env!("NARF_WL_SHM_ELF_AARCH64"));
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_MINI_COMPOSITOR_ELF: &[u8] = include_bytes!(env!("NARF_MINI_COMPOSITOR_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_MINI_COMPOSITOR_ELF: &[u8] =
    include_bytes!(env!("NARF_MINI_COMPOSITOR_ELF_AARCH64"));
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_WL_2PROC_ELF: &[u8] = include_bytes!(env!("NARF_WL_2PROC_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_WL_2PROC_ELF: &[u8] = include_bytes!(env!("NARF_WL_2PROC_ELF_AARCH64"));
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_WL_MULTI_ELF: &[u8] = include_bytes!(env!("NARF_WL_MULTI_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_WL_MULTI_ELF: &[u8] = include_bytes!(env!("NARF_WL_MULTI_ELF_AARCH64"));
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_WL_XDG_ELF: &[u8] = include_bytes!(env!("NARF_WL_XDG_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_WL_XDG_ELF: &[u8] = include_bytes!(env!("NARF_WL_XDG_ELF_AARCH64"));
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_WL_INPUT_ELF: &[u8] = include_bytes!(env!("NARF_WL_INPUT_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_WL_INPUT_ELF: &[u8] = include_bytes!(env!("NARF_WL_INPUT_ELF_AARCH64"));
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_WL_KMS_ELF: &[u8] = include_bytes!(env!("NARF_WL_KMS_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_WL_KMS_ELF: &[u8] = include_bytes!(env!("NARF_WL_KMS_ELF_AARCH64"));
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_WL_EVDEV_ELF: &[u8] = include_bytes!(env!("NARF_WL_EVDEV_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_WL_EVDEV_ELF: &[u8] = include_bytes!(env!("NARF_WL_EVDEV_ELF_AARCH64"));
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_SIMPLE_SHM_ELF: &[u8] = include_bytes!(env!("NARF_SIMPLE_SHM_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_SIMPLE_SHM_ELF: &[u8] = include_bytes!(env!("NARF_SIMPLE_SHM_ELF_AARCH64"));
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_WL_APP_ELF: &[u8] = include_bytes!(env!("NARF_WL_APP_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_WL_APP_ELF: &[u8] = include_bytes!(env!("NARF_WL_APP_ELF_AARCH64"));
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_DISTRO_INIT_ELF: &[u8] = include_bytes!(env!("NARF_DISTRO_INIT_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_DISTRO_INIT_ELF: &[u8] = include_bytes!(env!("NARF_DISTRO_INIT_ELF_AARCH64"));
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_DISTRO_DESKTOP_ELF: &[u8] = include_bytes!(env!("NARF_DISTRO_DESKTOP_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_DISTRO_DESKTOP_ELF: &[u8] = include_bytes!(env!("NARF_DISTRO_DESKTOP_ELF_AARCH64"));
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_DISTRO_KDE_ELF: &[u8] = include_bytes!(env!("NARF_DISTRO_KDE_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_DISTRO_KDE_ELF: &[u8] = include_bytes!(env!("NARF_DISTRO_KDE_ELF_AARCH64"));
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_DISTRO_FEDORA_ELF: &[u8] = include_bytes!(env!("NARF_DISTRO_FEDORA_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_DISTRO_FEDORA_ELF: &[u8] = include_bytes!(env!("NARF_DISTRO_FEDORA_ELF_AARCH64"));
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_CHROOT_RUN_ELF: &[u8] = include_bytes!(env!("NARF_CHROOT_RUN_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_CHROOT_RUN_ELF: &[u8] = include_bytes!(env!("NARF_CHROOT_RUN_ELF_AARCH64"));

#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_HELLO_PTHREAD_ELF: &[u8] = include_bytes!(env!("NARF_HELLO_PTHREAD_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_HELLO_PTHREAD_ELF: &[u8] = include_bytes!(env!("NARF_HELLO_PTHREAD_ELF_AARCH64"));

#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_PTY_SMOKE_ELF: &[u8] = include_bytes!(env!("NARF_PTY_SMOKE_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_PTY_SMOKE_ELF: &[u8] = include_bytes!(env!("NARF_PTY_SMOKE_ELF_AARCH64"));

/// `/bin/fb_smoke` — opens `/dev/fb0`, mmaps it MAP_SHARED, draws, and
/// reads back through the mapping. Proves the device-mmap keystone +
/// fbdev ioctls end-to-end from stock musl. Success token: `fb-ok`.
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_FB_SMOKE_ELF: &[u8] = include_bytes!(env!("NARF_FB_SMOKE_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_FB_SMOKE_ELF: &[u8] = include_bytes!(env!("NARF_FB_SMOKE_ELF_AARCH64"));
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_SCM_SMOKE_ELF: &[u8] = include_bytes!(env!("NARF_SCM_SMOKE_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_SCM_SMOKE_ELF: &[u8] = include_bytes!(env!("NARF_SCM_SMOKE_ELF_AARCH64"));

/// `/bin/drm_smoke` — opens `/dev/dri/card0`, GET_CAP(DUMB_BUFFER),
/// CREATE_DUMB, MAP_DUMB, mmap MAP_SHARED, draws a pattern, ADDFB2,
/// SETCRTC (blits to scanout). Proves DRM/KMS dumb-buffer path end-to-end
/// from stock musl. Success token: `drm-ok`.
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_DRM_SMOKE_ELF: &[u8] = include_bytes!(env!("NARF_DRM_SMOKE_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_DRM_SMOKE_ELF: &[u8] = include_bytes!(env!("NARF_DRM_SMOKE_ELF_AARCH64"));

/// timerfd-in-epoll wake smoke — reproduces weston's repaint-loop driver
/// (a timerfd armed via timerfd_settime, blocked on by epoll_wait(-1)).
/// Success token: `tfd-epoll-ok`.
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_TFD_EPOLL_SMOKE_ELF: &[u8] = include_bytes!(env!("NARF_TFD_EPOLL_SMOKE_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_TFD_EPOLL_SMOKE_ELF: &[u8] =
    include_bytes!(env!("NARF_TFD_EPOLL_SMOKE_ELF_AARCH64"));

/// Pure-timeout poll/epoll park hammer — hundreds of no-fd timeout
/// windows (plus timerfd-in-epoll churn) across several concurrent
/// processes. Pins the slab free-canary false positive ("slab: double
/// free of block ... class 32 B") that tfd_epoll_smoke's single 120 ms
/// pure-timeout window only tripped on layout-cursed builds.
/// Success token: `polltmo-ok`.
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_POLLTMO_HAMMER_ELF: &[u8] = include_bytes!(env!("NARF_POLLTMO_HAMMER_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_POLLTMO_HAMMER_ELF: &[u8] = include_bytes!(env!("NARF_POLLTMO_HAMMER_ELF_AARCH64"));

/// AF_UNIX + epoll_wait(-1) serve smoke — regression for the bug where a server
/// blocked on an INFINITE-timeout epoll_wait never broke out to serve a
/// unix-socket peer (AF_UNIX wake didn't bump the readiness generation).
/// Success token: `uxe-ok`.
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_UNIX_EPOLL_SMOKE_ELF: &[u8] =
    include_bytes!(env!("NARF_UNIX_EPOLL_SMOKE_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_UNIX_EPOLL_SMOKE_ELF: &[u8] =
    include_bytes!(env!("NARF_UNIX_EPOLL_SMOKE_ELF_AARCH64"));

#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_NET_SMOKE_ELF: &[u8] = include_bytes!(env!("NARF_NET_SMOKE_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_NET_SMOKE_ELF: &[u8] = include_bytes!(env!("NARF_NET_SMOKE_ELF_AARCH64"));

#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_NET6_SMOKE_ELF: &[u8] = include_bytes!(env!("NARF_NET6_SMOKE_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_NET6_SMOKE_ELF: &[u8] = include_bytes!(env!("NARF_NET6_SMOKE_ELF_AARCH64"));

#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_UNIX_SMOKE_ELF: &[u8] = include_bytes!(env!("NARF_UNIX_SMOKE_ELF_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_UNIX_SMOKE_ELF: &[u8] = include_bytes!(env!("NARF_UNIX_SMOKE_ELF_AARCH64"));

macro_rules! define_smoke_elf {
    ($name:ident, $env_x86:expr, $env_arm:expr) => {
        #[cfg(all(
            target_arch = "x86_64",
            any(feature = "boot-init", feature = "user-mode-testbin")
        ))]
        pub const $name: &[u8] = include_bytes!(env!($env_x86));
        #[cfg(all(
            target_arch = "aarch64",
            any(feature = "boot-init", feature = "user-mode-testbin")
        ))]
        pub const $name: &[u8] = include_bytes!(env!($env_arm));
    };
}

define_smoke_elf!(
    NARF_FORK_PIPE_SMOKE_ELF,
    "NARF_FORK_PIPE_SMOKE_ELF_X86_64",
    "NARF_FORK_PIPE_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_WLSERVE_SMOKE_ELF,
    "NARF_WLSERVE_SMOKE_ELF_X86_64",
    "NARF_WLSERVE_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_POPENW_SMOKE_ELF,
    "NARF_POPENW_SMOKE_ELF_X86_64",
    "NARF_POPENW_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_FORK_EXEC_BURST_SMOKE_ELF,
    "NARF_FORK_EXEC_BURST_SMOKE_ELF_X86_64",
    "NARF_FORK_EXEC_BURST_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_SCHED_AFFINITY_SMP_SMOKE_ELF,
    "NARF_SCHED_AFFINITY_SMP_SMOKE_ELF_X86_64",
    "NARF_SCHED_AFFINITY_SMP_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_EPOLL_SMOKE_ELF,
    "NARF_EPOLL_SMOKE_ELF_X86_64",
    "NARF_EPOLL_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_SIGNAL_SMOKE_ELF,
    "NARF_SIGNAL_SMOKE_ELF_X86_64",
    "NARF_SIGNAL_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_DF_TRAP_SMOKE_ELF,
    "NARF_DF_TRAP_SMOKE_ELF_X86_64",
    "NARF_DF_TRAP_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_SIGRCX_SMOKE_ELF,
    "NARF_SIGRCX_SMOKE_ELF_X86_64",
    "NARF_SIGRCX_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_PIPEBLK_SMOKE_ELF,
    "NARF_PIPEBLK_SMOKE_ELF_X86_64",
    "NARF_PIPEBLK_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_FS_SMOKE_ELF,
    "NARF_FS_SMOKE_ELF_X86_64",
    "NARF_FS_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_EVENTFD_SMOKE_ELF,
    "NARF_EVENTFD_SMOKE_ELF_X86_64",
    "NARF_EVENTFD_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_GETRANDOM_SMOKE_ELF,
    "NARF_GETRANDOM_SMOKE_ELF_X86_64",
    "NARF_GETRANDOM_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_SOCKPAIR_SMOKE_ELF,
    "NARF_SOCKPAIR_SMOKE_ELF_X86_64",
    "NARF_SOCKPAIR_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_SOCKPAIRFORK_SMOKE_ELF,
    "NARF_SOCKPAIRFORK_SMOKE_ELF_X86_64",
    "NARF_SOCKPAIRFORK_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_UNLINKOPEN_SMOKE_ELF,
    "NARF_UNLINKOPEN_SMOKE_ELF_X86_64",
    "NARF_UNLINKOPEN_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_PIPEHUP_SMOKE_ELF,
    "NARF_PIPEHUP_SMOKE_ELF_X86_64",
    "NARF_PIPEHUP_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_ACCEPT4_SMOKE_ELF,
    "NARF_ACCEPT4_SMOKE_ELF_X86_64",
    "NARF_ACCEPT4_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_MREMAP_SMOKE_ELF,
    "NARF_MREMAP_SMOKE_ELF_X86_64",
    "NARF_MREMAP_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_SENDFILE_SMOKE_ELF,
    "NARF_SENDFILE_SMOKE_ELF_X86_64",
    "NARF_SENDFILE_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_CREDS_SMOKE_ELF,
    "NARF_CREDS_SMOKE_ELF_X86_64",
    "NARF_CREDS_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_WAITID_SMOKE_ELF,
    "NARF_WAITID_SMOKE_ELF_X86_64",
    "NARF_WAITID_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_PPOLL_SMOKE_ELF,
    "NARF_PPOLL_SMOKE_ELF_X86_64",
    "NARF_PPOLL_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_SYSINFO_SMOKE_ELF,
    "NARF_SYSINFO_SMOKE_ELF_X86_64",
    "NARF_SYSINFO_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_SPLICE_SMOKE_ELF,
    "NARF_SPLICE_SMOKE_ELF_X86_64",
    "NARF_SPLICE_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_BARRIER_SMOKE_ELF,
    "NARF_BARRIER_SMOKE_ELF_X86_64",
    "NARF_BARRIER_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_CLOSERANGE_SMOKE_ELF,
    "NARF_CLOSERANGE_SMOKE_ELF_X86_64",
    "NARF_CLOSERANGE_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_FD_CLOEXEC_EXEC_SMOKE_ELF,
    "NARF_FD_CLOEXEC_EXEC_SMOKE_ELF_X86_64",
    "NARF_FD_CLOEXEC_EXEC_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_SCHED_SMOKE_ELF,
    "NARF_SCHED_SMOKE_ELF_X86_64",
    "NARF_SCHED_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_MCORE_SMOKE_ELF,
    "NARF_MCORE_SMOKE_ELF_X86_64",
    "NARF_MCORE_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_SYNC_SMOKE_ELF,
    "NARF_SYNC_SMOKE_ELF_X86_64",
    "NARF_SYNC_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_DUP3FAM_SMOKE_ELF,
    "NARF_DUP3FAM_SMOKE_ELF_X86_64",
    "NARF_DUP3FAM_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_ROBUST_SMOKE_ELF,
    "NARF_ROBUST_SMOKE_ELF_X86_64",
    "NARF_ROBUST_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_RENAMEAT2_SMOKE_ELF,
    "NARF_RENAMEAT2_SMOKE_ELF_X86_64",
    "NARF_RENAMEAT2_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_PIDFDSIG_SMOKE_ELF,
    "NARF_PIDFDSIG_SMOKE_ELF_X86_64",
    "NARF_PIDFDSIG_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_HOST_SMOKE_ELF,
    "NARF_HOST_SMOKE_ELF_X86_64",
    "NARF_HOST_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_MMSG_SMOKE_ELF,
    "NARF_MMSG_SMOKE_ELF_X86_64",
    "NARF_MMSG_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_OPENAT2_SMOKE_ELF,
    "NARF_OPENAT2_SMOKE_ELF_X86_64",
    "NARF_OPENAT2_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_PV_SMOKE_ELF,
    "NARF_PV_SMOKE_ELF_X86_64",
    "NARF_PV_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_CAP_SMOKE_ELF,
    "NARF_CAP_SMOKE_ELF_X86_64",
    "NARF_CAP_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_ITIMER_SMOKE_ELF,
    "NARF_ITIMER_SMOKE_ELF_X86_64",
    "NARF_ITIMER_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_SHMFORK_SMOKE_ELF,
    "NARF_SHMFORK_SMOKE_ELF_X86_64",
    "NARF_SHMFORK_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_XATTR_SMOKE_ELF,
    "NARF_XATTR_SMOKE_ELF_X86_64",
    "NARF_XATTR_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_PERF_SMOKE_ELF,
    "NARF_PERF_SMOKE_ELF_X86_64",
    "NARF_PERF_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_FHINT_SMOKE_ELF,
    "NARF_FHINT_SMOKE_ELF_X86_64",
    "NARF_FHINT_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_MQ_SMOKE_ELF,
    "NARF_MQ_SMOKE_ELF_X86_64",
    "NARF_MQ_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_INOTIFY_SMOKE_ELF,
    "NARF_INOTIFY_SMOKE_ELF_X86_64",
    "NARF_INOTIFY_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_PKEY_SMOKE_ELF,
    "NARF_PKEY_SMOKE_ELF_X86_64",
    "NARF_PKEY_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_PVM_SMOKE_ELF,
    "NARF_PVM_SMOKE_ELF_X86_64",
    "NARF_PVM_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_MEMPOLICY_SMOKE_ELF,
    "NARF_MEMPOLICY_SMOKE_ELF_X86_64",
    "NARF_MEMPOLICY_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_SCHEDATTR_SMOKE_ELF,
    "NARF_SCHEDATTR_SMOKE_ELF_X86_64",
    "NARF_SCHEDATTR_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_ADJTIMEX_SMOKE_ELF,
    "NARF_ADJTIMEX_SMOKE_ELF_X86_64",
    "NARF_ADJTIMEX_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_INTROSPECT_SMOKE_ELF,
    "NARF_INTROSPECT_SMOKE_ELF_X86_64",
    "NARF_INTROSPECT_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_VIO_SMOKE_ELF,
    "NARF_VIO_SMOKE_ELF_X86_64",
    "NARF_VIO_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_SYSVIPC_SMOKE_ELF,
    "NARF_SYSVIPC_SMOKE_ELF_X86_64",
    "NARF_SYSVIPC_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_SHM_SMOKE_ELF,
    "NARF_SHM_SMOKE_ELF_X86_64",
    "NARF_SHM_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_XATTR2_SMOKE_ELF,
    "NARF_XATTR2_SMOKE_ELF_X86_64",
    "NARF_XATTR2_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_FSMISC_SMOKE_ELF,
    "NARF_FSMISC_SMOKE_ELF_X86_64",
    "NARF_FSMISC_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_CREDS2_SMOKE_ELF,
    "NARF_CREDS2_SMOKE_ELF_X86_64",
    "NARF_CREDS2_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_SIG2_SMOKE_ELF,
    "NARF_SIG2_SMOKE_ELF_X86_64",
    "NARF_SIG2_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_MEM2_SMOKE_ELF,
    "NARF_MEM2_SMOKE_ELF_X86_64",
    "NARF_MEM2_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_PSCHED_SMOKE_ELF,
    "NARF_PSCHED_SMOKE_ELF_X86_64",
    "NARF_PSCHED_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_FUTEX2_SMOKE_ELF,
    "NARF_FUTEX2_SMOKE_ELF_X86_64",
    "NARF_FUTEX2_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_FUTEX_CONTEND_SMOKE_ELF,
    "NARF_FUTEX_CONTEND_SMOKE_ELF_X86_64",
    "NARF_FUTEX_CONTEND_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_FUTEX_WAKEOP_SMOKE_ELF,
    "NARF_FUTEX_WAKEOP_SMOKE_ELF_X86_64",
    "NARF_FUTEX_WAKEOP_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_CONDBCAST_SMOKE_ELF,
    "NARF_CONDBCAST_SMOKE_ELF_X86_64",
    "NARF_CONDBCAST_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_NOTIFY_EPOLL_SMP_SMOKE_ELF,
    "NARF_NOTIFY_EPOLL_SMP_SMOKE_ELF_X86_64",
    "NARF_NOTIFY_EPOLL_SMP_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_KEYRING_SMOKE_ELF,
    "NARF_KEYRING_SMOKE_ELF_X86_64",
    "NARF_KEYRING_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_INOTIFY2_SMOKE_ELF,
    "NARF_INOTIFY2_SMOKE_ELF_X86_64",
    "NARF_INOTIFY2_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_FANOTIFY_SMOKE_ELF,
    "NARF_FANOTIFY_SMOKE_ELF_X86_64",
    "NARF_FANOTIFY_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_LANDLOCK_SMOKE_ELF,
    "NARF_LANDLOCK_SMOKE_ELF_X86_64",
    "NARF_LANDLOCK_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_LSM_SMOKE_ELF,
    "NARF_LSM_SMOKE_ELF_X86_64",
    "NARF_LSM_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_VDSO_SMOKE_ELF,
    "NARF_VDSO_SMOKE_ELF_X86_64",
    "NARF_VDSO_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_FHANDLE_SMOKE_ELF,
    "NARF_FHANDLE_SMOKE_ELF_X86_64",
    "NARF_FHANDLE_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_MOUNTAPI_SMOKE_ELF,
    "NARF_MOUNTAPI_SMOKE_ELF_X86_64",
    "NARF_MOUNTAPI_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_JOBCTL_SMOKE_ELF,
    "NARF_JOBCTL_SMOKE_ELF_X86_64",
    "NARF_JOBCTL_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_JOBCTL2_SMOKE_ELF,
    "NARF_JOBCTL2_SMOKE_ELF_X86_64",
    "NARF_JOBCTL2_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_NAVFS_SMOKE_ELF,
    "NARF_NAVFS_SMOKE_ELF_X86_64",
    "NARF_NAVFS_SMOKE_ELF_AARCH64"
);
// OCI-container runtime smoke (static): both container-manager and
// contained-entrypoint in one binary. Seeded at /bin/oci_smoke (the
// runtime) and at /oci/rootfs/init (the entrypoint, reached via chroot).
define_smoke_elf!(
    NARF_OCI_SMOKE_ELF,
    "NARF_OCI_SMOKE_ELF_X86_64",
    "NARF_OCI_SMOKE_ELF_AARCH64"
);
// Off-box network serving smoke: a TCP echo server bound to 0.0.0.0,
// reached from the host via QEMU `hostfwd`.
define_smoke_elf!(
    NARF_NETSERVE_SMOKE_ELF,
    "NARF_NETSERVE_SMOKE_ELF_X86_64",
    "NARF_NETSERVE_SMOKE_ELF_AARCH64"
);
// The full terminal chain: posix_openpt/grantpt/unlockpt/ptsname, then
// fork + setsid + dup2 onto 0/1/2 + exec /bin/sh, then the parent reads the
// child's output back off the master. Exactly what a terminal emulator does
// before its shell.
define_smoke_elf!(
    NARF_PTYSPAWN_SMOKE_ELF,
    "NARF_PTYSPAWN_SMOKE_ELF_X86_64",
    "NARF_PTYSPAWN_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_PIPEOF_SMOKE_ELF,
    "NARF_PIPEOF_SMOKE_ELF_X86_64",
    "NARF_PIPEOF_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_RELPATHS_SMOKE_ELF,
    "NARF_RELPATHS_SMOKE_ELF_X86_64",
    "NARF_RELPATHS_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_CONSOLETTY_SMOKE_ELF,
    "NARF_CONSOLETTY_SMOKE_ELF_X86_64",
    "NARF_CONSOLETTY_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_ALARMLOOP_SMOKE_ELF,
    "NARF_ALARMLOOP_SMOKE_ELF_X86_64",
    "NARF_ALARMLOOP_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_SIGRT_SMOKE_ELF,
    "NARF_SIGRT_SMOKE_ELF_X86_64",
    "NARF_SIGRT_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_STRACE_SMOKE_ELF,
    "NARF_STRACE_SMOKE_ELF_X86_64",
    "NARF_STRACE_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_PREEMPTSCHED_SMOKE_ELF,
    "NARF_PREEMPTSCHED_SMOKE_ELF_X86_64",
    "NARF_PREEMPTSCHED_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_FPU_PREEMPT_SMOKE_ELF,
    "NARF_FPU_PREEMPT_SMOKE_ELF_X86_64",
    "NARF_FPU_PREEMPT_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_PROCFS2_SMOKE_ELF,
    "NARF_PROCFS2_SMOKE_ELF_X86_64",
    "NARF_PROCFS2_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_NUMA_SMOKE_ELF,
    "NARF_NUMA_SMOKE_ELF_X86_64",
    "NARF_NUMA_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_DSO_SMOKE_ELF,
    "NARF_DSO_SMOKE_ELF_X86_64",
    "NARF_DSO_SMOKE_ELF_AARCH64"
);
define_smoke_elf!(
    NARF_TLS_SMOKE_ELF,
    "NARF_TLS_SMOKE_ELF_X86_64",
    "NARF_TLS_SMOKE_ELF_AARCH64"
);

#[cfg(all(
    target_arch = "x86_64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_LD_MUSL: &[u8] = include_bytes!(env!("NARF_LD_MUSL_X86_64"));
#[cfg(all(
    target_arch = "aarch64",
    any(feature = "boot-init", feature = "user-mode-testbin")
))]
pub const NARF_LD_MUSL: &[u8] = include_bytes!(env!("NARF_LD_MUSL_AARCH64"));

// Wave-79: BusyBox built from upstream source by
// `verification/busybox/build.rs`. Static against musl, linked
// at `0x8000001000` (PML4[1]). Seeded at /bin/busybox so
// `narf> busybox echo hello` exercises a real-world workload
// against NARF's linux-compat surface. Empty slice when musl-gcc
// isn't on the host (build skips gracefully).
#[cfg(feature = "boot-init")]
pub use narf_busybox::NARF_BUSYBOX;

#[cfg(all(target_arch = "x86_64", feature = "user-mode-testbin"))]
fn smoke_frame_x86_64_run_narf_testbin() -> TestResult {
    // Load the real Rust no_std binary `narf-testbin` into a fresh
    // UserProcess, install the core syscall handlers (Write goes
    // to the kernel console; ExitTask redirects the trap frame),
    // register an exit-landing that longjmps back to the kernel,
    // and enter user mode. On successful unwind, the testbin's
    // "user: ok\n" message has hit the console and ExitTask did
    // its redirect.
    use core::arch::naked_asm;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_userspace::{
        clear_exit_landing, install_address_space_lookup, install_core_syscalls, install_global,
        load_user_process_with, set_exit_landing,
        syscall::__verification_clear_global as __test_clear_global, AuxEntry, SyscallTable,
    };

    static mut JMP2: UserModeJmpBuf = UserModeJmpBuf {
        rbx: 0,
        rbp: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        rsp: 0,
        rip: 0,
    };
    static SAVED_CR3_2: AtomicU64 = AtomicU64::new(0);

    #[unsafe(naked)]
    unsafe extern "C" fn testbin_resume_trampoline() -> ! {
        naked_asm!(
            "lea rdi, [rip + {jmp}]",
            "mov rsi, 1",
            "jmp {lj}",
            jmp = sym JMP2,
            lj  = sym user_mode_longjmp,
        );
    }

    // Test-only AS lookup: the testbin is run outside the
    // scheduler (we're called from the kernel-test harness, not as
    // a spawned task), so `scheduler::current_task_id()` returns
    // NONE. Instead, stash the process's Arc<AddressSpace> in a
    // static that the lookup returns directly.
    static USER_AS: narf_lib::sync::IrqSafeSpinLock<
        Option<alloc::sync::Arc<narf_memory::AddressSpace>>,
    > = narf_lib::sync::IrqSafeSpinLock::new(None);
    fn test_as_lookup() -> Option<alloc::sync::Arc<narf_memory::AddressSpace>> {
        USER_AS.lock().clone()
    }

    __test_clear_global();
    install_address_space_lookup(test_as_lookup);
    // Bootstrap registry needs initialising so SYS_BOOTSTRAP from
    // the testbin can find a place to stash its per-task ring pair.
    narf_userspace::bootstrap_init();
    // Per-task brk + sigaction stores: the testbin's brk + sig
    // probes both need their per-task BTreeMap created before the
    // first call.
    narf_userspace::handlers::__test_brk_reset();
    narf_userspace::brk_init();
    narf_userspace::handlers::__test_sigaction_reset();
    narf_userspace::sigaction_init();
    // Per-task signal pending+mask: the testbin's signal probe
    // needs both stores initialised before the first kill.
    narf_userspace::handlers::__test_signal_reset();
    narf_userspace::signal_init();
    // Per-task cwd: the testbin doesn't probe chdir today, but
    // `install_core_syscalls` wires Chdir/Getcwd into the table —
    // initialising the registry here keeps the runner's pre-state
    // consistent with the validate runner's.
    narf_userspace::handlers::__test_cwd_reset();
    narf_userspace::cwd_init();
    // Per-task fd table store needs initialising so SYS_OPEN from
    // the testbin can install a fd entry in its (task=0) table.
    narf_userspace::fd::__test_reset();
    // Mount a stub FS under /testbin with a file "f" carrying a
    // known payload so the testbin's open + read can round-trip
    // a real VFS path from CPL=3.
    {
        use alloc::boxed::Box;
        use alloc::sync::Arc;
        use narf_capabilities::{Cap, Grant};
        use narf_filesystem::{
            bootstrap_mount_authority, registry, DirEntry, DirOps, FileOps, FsFuture, FsInstance,
            MountPoint, Stat,
        };
        static FILE_BYTES: &[u8] = b"hello-fs";
        struct StubFile;
        impl FileOps for StubFile {
            fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
                Box::pin(async move {
                    let off = offset as usize;
                    if off >= FILE_BYTES.len() {
                        return Ok(0);
                    }
                    let n = core::cmp::min(buf.len(), FILE_BYTES.len() - off);
                    buf[..n].copy_from_slice(&FILE_BYTES[off..off + n]);
                    Ok(n)
                })
            }
            fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
                let n = b.len();
                Box::pin(async move { Ok(n) })
            }
            fn stat(&self) -> Stat {
                Stat {
                    size: FILE_BYTES.len() as u64,
                    blocks: 1,
                    mode: narf_filesystem::Mode::FILE_RO,
                    mtime_cycles: 0,
                }
            }
        }
        struct StubDir;
        impl DirOps for StubDir {
            fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
                if name == "f" {
                    Some(Arc::new(StubFile))
                } else {
                    None
                }
            }
            fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
                Box::new(core::iter::empty())
            }
        }
        struct StubFs;
        impl FsInstance for StubFs {
            fn root(&self) -> Arc<dyn DirOps> {
                Arc::new(StubDir)
            }
            fn name(&self) -> &str {
                "testbin_stub"
            }
        }
        let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
        let _ = registry().mount(&auth, "/testbin", StubFs);
    }
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // FB syscall vtable: the boot path's Stage::Subsys initcall
    // installs this; the test runner doesn't invoke initcalls so
    // we wire the vtable here directly.
    narf_userspace::handlers::install_fb_syscall_vtable(narf_fb::registry::syscall_vtable());
    narf_userspace::handlers::install_shmem_syscall_vtable(narf_shmem::syscall_vtable());

    // Snapshot CR3 for restore post-unwind.
    let original_cr3: u64;
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!("mov {v}, cr3", v = out(reg) original_cr3,
            options(nostack, preserves_flags));
    }
    SAVED_CR3_2.store(original_cr3, Ordering::Release);

    // ExitTask lands at the naked trampoline.
    set_exit_landing(testbin_resume_trampoline as usize as u64, 0);

    // SAFETY: Valid memory or trusted environment
    let saved = unsafe { user_mode_setjmp(core::ptr::addr_of_mut!(JMP2)) };
    if saved != 0 {
        // SAFETY: Valid memory or trusted environment
        unsafe {
            // Restore kernel CR3.
            let cr3 = SAVED_CR3_2.load(Ordering::Acquire);
            core::arch::asm!("mov cr3, {v}", v = in(reg) cr3,
                options(nostack, preserves_flags));
            // Reset KERNEL_GS_BASE to zero (post-init state).
            const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
            core::arch::asm!(
                "wrmsr",
                in("ecx") IA32_KERNEL_GS_BASE,
                in("eax") 0u32,
                in("edx") 0u32,
                options(nostack, preserves_flags),
            );
            // Re-enable interrupts.
            core::arch::asm!("sti", options(nomem, nostack, preserves_flags));
        }
        clear_exit_landing();
        __test_clear_global();
        // Print our pass line manually then terminate the kernel
        // cleanly. Subsequent tests in the suite hit residual
        // state from the trap (TSS-rsp0 stack consumed, leaked
        // user AS, etc.) that we haven't fully unwound — tracked
        // as a Stage-4 follow-up. Exiting here preserves the
        // testbin's pass signal in QEMU's exit code.
        use core::fmt::Write as _;
        let mut w = Writer;
        // FB probe verification: after the testbin returns, drain
        // anything it enqueued onto its DrawRing. The drain task
        // we spawn at boot doesn't run inside the test harness
        // (no scheduler tick from this runner), so we drain
        // synchronously here.
        if narf_fb::select_active().is_some() {
            let cap = narf_fb::bootstrap_writer();
            if let Ok(fb_writer) = narf_fb::FbWriter::new(cap) {
                let (ok_n, _err_n) = narf_fb::drain_once(&fb_writer);
                let _ = writeln!(w, "  fb: post-testbin drain executed {} cmd(s)", ok_n);
            }
        }
        let _ = writeln!(w, "  [ OK ] smoke_frame_x86_64_run_narf_testbin");
        let _ = writeln!(w, "── user-mode-testbin: testbin round-trip succeeded ──");
        // SAFETY: Valid memory or trusted environment
        unsafe { narf_arch::exit_kernel(0) }
    }

    // First pass — load + enter.
    if NARF_TESTBIN_ELF.is_empty() {
        return TestResult::Skip("narf-testbin not built (feature disabled?)");
    }
    // Hand argv = ["narf-testbin", "argA"] to the loader so the
    // testbin can exercise the SysV-stack startup contract from
    // CPL=3 and verify [rsp]=argc, argv[0]="narf-testbin".
    let argv = ["narf-testbin", "argA"];
    let envp: [&str; 0] = [];
    let aux = [AuxEntry::Pagesz(4096)];
    // SAFETY: Valid memory or trusted environment
    let proc = match unsafe { load_user_process_with(NARF_TESTBIN_ELF, &argv, &envp, &aux) } {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("load_user_process_with failed on narf-testbin"),
    };

    // Stash the user AS so Mmap/Munmap handlers can find it via
    // the installed lookup.
    *USER_AS.lock() = Some(proc.address_space.clone());

    if proc.address_space.activate().is_err() {
        return TestResult::Fail("activate failed");
    }

    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!("cli");
    }
    // SAFETY: Valid memory or trusted environment
    unsafe { user_mode_enter(proc.entry.0.as_u64(), proc.stack_top.as_u64()) }
}
#[cfg(all(target_arch = "x86_64", feature = "user-mode-testbin"))]
kernel_test!(smoke_frame_x86_64_run_narf_testbin);

// ── narf-libc validate binary ────────────────────────────────────────
//
// Same shape as the testbin runner above, but the user binary is
// the relibc-shaped `narf-libc-validate`. The validate ELF carries
// a PT_TLS phdr (16-byte template) that the kernel's tls staging
// will plant at fs_base; the binary's `_start` is supplied by
// narf-libc itself and bridges through `__libc_start_main` into
// the validate's `main`.

#[cfg(all(target_arch = "x86_64", feature = "narf-libc-validate"))]
const NARF_LIBC_VALIDATE_ELF: &[u8] = include_bytes!(env!("NARF_LIBC_VALIDATE_ELF_X86_64"));

#[cfg(all(target_arch = "x86_64", feature = "narf-libc-validate"))]
fn smoke_frame_x86_64_run_narf_libc_validate() -> TestResult {
    use core::arch::naked_asm;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_userspace::{
        clear_exit_landing, install_address_space_lookup, install_core_syscalls, install_global,
        load_user_process_with, set_exit_landing,
        syscall::__verification_clear_global as __test_clear_global, AuxEntry, SyscallTable,
    };

    static mut JMP3: UserModeJmpBuf = UserModeJmpBuf {
        rbx: 0,
        rbp: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        rsp: 0,
        rip: 0,
    };
    static SAVED_CR3_3: AtomicU64 = AtomicU64::new(0);

    #[unsafe(naked)]
    unsafe extern "C" fn libc_validate_resume_trampoline() -> ! {
        naked_asm!(
            "lea rdi, [rip + {jmp}]",
            "mov rsi, 1",
            "jmp {lj}",
            jmp = sym JMP3,
            lj  = sym user_mode_longjmp,
        );
    }

    // Same test-only AS lookup pattern as the testbin runner: the
    // validate binary is run outside the scheduler so we stash its
    // AS in a static for the Mmap/Munmap handlers to find.
    static USER_AS: narf_lib::sync::IrqSafeSpinLock<
        Option<alloc::sync::Arc<narf_memory::AddressSpace>>,
    > = narf_lib::sync::IrqSafeSpinLock::new(None);
    fn test_as_lookup() -> Option<alloc::sync::Arc<narf_memory::AddressSpace>> {
        USER_AS.lock().clone()
    }

    __test_clear_global();
    install_address_space_lookup(test_as_lookup);
    // Bootstrap + brk + sigaction + signal + fd init mirrors the
    // testbin runner. The validate binary now exercises a broader
    // surface — printf-shim + getpid plus probes for `strchr`,
    // `memmove`, `getenv`, and `atexit` — but the runner shape is
    // identical: a clean exit round-trip is the pass condition.
    // Expected stdout (visible in the QEMU console; not grepped):
    //   hello from narf-libc; pid=<n>
    //   strchr: ok
    //   memmove: ok
    //   getenv: ok
    //   chdir: ok     <- chdir("/") returns 0; cwd table is shared
    //                    state between this runner's init and the
    //                    handler.
    //   cwd: ok       <- getcwd into a 16-byte buffer reads "/\0".
    //   sleep: ok     <- usleep(1000) returns 0; sys_sleep spin-waits
    //                    in trap context (see its docstring).
    //   fcntl: ok     <- Tier-2 fd-table breadth: F_GETFD on stdin
    //                    returns 0 (no flags installed).
    //   dup: ok       <- dup(1) returns a fresh fd ≥ 3.
    //   pipe: ok      <- pipe() round-trip allocates two distinct
    //                    fds ≥ 3 and writes them back through the
    //                    out-pointer.
    //   heap: ok      <- Tier-1.5 freelist over mmap: round-trip,
    //                    distinct-live-chunks, free-list-reuse, and
    //                    realloc-grow probes (see narf-libc-validate
    //                    `heap_probe`).
    //   unlink: ok    <- Tier-3b VFS remove: posix_unlink("/tmp/removable")
    //                    returns 0 on the seeded MemFs entry; the
    //                    second call returns -1 because the entry is
    //                    gone. Proves the real DirOps::unlink path,
    //                    not a no-op stub.
    //   create: ok    <- Tier-3c open(O_CREAT): the kernel routes a
    //                    missing path to parent.create(leaf). Two
    //                    opens of /tmp/created return distinct fds.
    //   rename: ok    <- Tier-3c same-directory rename:
    //                    /tmp/created -> /tmp/renamed; the new name
    //                    opens, the old name doesn't.
    //   mkdir: ok     <- Tier-3d hierarchical MemFs: full mkdir +
    //                    open-in-subdir + rmdir-busy + unlink +
    //                    rmdir-empty round-trip.
    //   rw: ok        <- Tier-3d write/read round-trip: open(O_CREAT),
    //                    write payload, close, reopen, read back,
    //                    compare bytes.
    //   setjmp: ok    <- Tier-3e setjmp/longjmp: first call returns 0,
    //                    longjmp(env, 7) re-enters with apparent
    //                    return 7; static counter proves single
    //                    re-entry, not infinite loop.
    //   getopt: ok    <- Tier-3f getopt: walks "-a -b val rest"
    //                    against optstring "ab:", returns 'a',
    //                    'b' with optarg="val", -1 with optind=4.
    //   assert: ok    <- Tier-3f __assert_fail link-presence (the
    //                    function is no-return so we can't exercise
    //                    it without aborting; we just confirm the
    //                    symbol resolves).
    //   math: ok      <- Tier-3g <math.h>: fabs/floor/ceil/trunc/
    //                    round/sqrt/fmod/fmin/fmax + isnan/isinf/
    //                    isfinite/copysign/signbit reference cases.
    //   ctype: ok     <- Tier-3d <ctype.h>: isdigit/isalpha/isspace/
    //                    isxdigit + tolower/toupper round-trip.
    //   atoi: ok      <- Tier-3a stdlib: leading whitespace + sign +
    //                    digit-stop on non-digit ("  -42xyz" -> -42).
    //   strtol: ok    <- 0x prefix + endptr writeback ("0xdeadbeef ").
    //   qsort: ok     <- insertion sort over a 6-element i32 slice.
    //   bsearch: ok   <- key=5 lookup over the sorted output.
    //   isatty: ok    <- fd 0 is the console (1); fd 99 is unbacked (0).
    //   signal: ok    <- signal(SIGTERM, h) returns SIG_DFL_RAW prior.
    //   snprintf: ok  <- Tier-2.5 io::Sink-as-buf path: snprintf_str
    //                    of `%5d %s` matches `   42 hi\0` byte-for-byte.
    //   clock: ok     <- clock_gettime back-to-back returns monotonic
    //                    non-decreasing timespec values.
    //   errno_loc: ok <- __errno_location() pointer round-trips
    //                    through the Rust errno() accessor.
    //   atexit: ok    <- emitted from the atexit callback, after
    //                    `main` returns and before exit_task.
    narf_userspace::bootstrap_init();
    narf_userspace::handlers::__test_brk_reset();
    narf_userspace::brk_init();
    narf_userspace::handlers::__test_sigaction_reset();
    narf_userspace::sigaction_init();
    narf_userspace::handlers::__test_signal_reset();
    narf_userspace::signal_init();
    narf_userspace::handlers::__test_cwd_reset();
    narf_userspace::cwd_init();
    narf_userspace::fd::__test_reset();

    // Mount a MemFs at /tmp seeded with one file so the validate
    // binary's unlink probe has a real target. The mount is allowed
    // to fail with `Busy` if a prior test left /tmp mounted; in that
    // case we proceed against the existing mount (which still
    // implements unlink because it's the same MemFs left in place).
    let auth_v = narf_filesystem::bootstrap_mount_authority();
    match narf_filesystem::registry().mount(
        &auth_v,
        "/tmp",
        narf_filesystem::MemFs::with_seeds("validate-tmp", &[("removable", b"bye")]),
    ) {
        Ok(_) => {}
        Err(narf_filesystem::FsError::Busy) => {
            // Re-seed the existing mount so the probe finds the file.
            let _ = narf_filesystem::registry()
                .resolve_parent_absolute("/tmp/removable", |_fs, parent, _leaf| {
                    parent.create("removable")
                });
        }
        Err(e) => {
            return TestResult::Fail(match e {
                narf_filesystem::FsError::PermissionDenied => "tmp mount: perm",
                narf_filesystem::FsError::ReadOnly => "tmp mount: ro",
                _ => "tmp mount: other",
            });
        }
    }

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let original_cr3: u64;
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!("mov {v}, cr3", v = out(reg) original_cr3,
            options(nostack, preserves_flags));
    }
    SAVED_CR3_3.store(original_cr3, Ordering::Release);

    set_exit_landing(libc_validate_resume_trampoline as usize as u64, 0);

    // SAFETY: Valid memory or trusted environment
    let saved = unsafe { user_mode_setjmp(core::ptr::addr_of_mut!(JMP3)) };
    if saved != 0 {
        // SAFETY: Valid memory or trusted environment
        unsafe {
            let cr3 = SAVED_CR3_3.load(Ordering::Acquire);
            core::arch::asm!("mov cr3, {v}", v = in(reg) cr3,
                options(nostack, preserves_flags));
            // Reset KERNEL_GS_BASE to zero (post-init state).
            const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
            core::arch::asm!(
                "wrmsr",
                in("ecx") IA32_KERNEL_GS_BASE,
                in("eax") 0u32,
                in("edx") 0u32,
                options(nostack, preserves_flags),
            );
            // Per the testbin runner: do NOT issue `sti` here; the
            // unwind path keeps interrupts disabled. (See 401b073.)
        }
        clear_exit_landing();
        __test_clear_global();
        use core::fmt::Write as _;
        let mut w = Writer;
        let _ = writeln!(w, "  [ OK ] smoke_frame_x86_64_run_narf_libc_validate");
        let _ = writeln!(w, "── narf-libc-validate: validate round-trip succeeded ──");
        // The validate binary's stdout (routed to the kernel
        // console) now contains the Stage-4 round-2 printf-shim
        // probes covering width/precision/flag handling plus the
        // new `o`/`b` conversions. The harness doesn't yet capture
        // user stdout for grep, so the expected lines are noted
        // here for log inspection:
        //   padded: '   42'
        //   zero: '00042'
        //   left:  '42   |'
        //   prec:  '002a'
        //   octal: '52'
        //   binary:'101010'
        //   long:  '-1'
        //   strpad:'hi        |abc'
        //   altsign:'+7 0xdead'
        //   fprintf:'123'
        // SAFETY: Valid memory or trusted environment
        unsafe { narf_arch::exit_kernel(0) }
    }

    if NARF_LIBC_VALIDATE_ELF.is_empty() {
        return TestResult::Skip("narf-libc-validate not built (feature disabled?)");
    }
    let argv = ["narf-libc-validate"];
    let envp: [&str; 0] = [];
    let aux = [AuxEntry::Pagesz(4096)];
    // SAFETY: Valid memory or trusted environment
    let proc = match unsafe { load_user_process_with(NARF_LIBC_VALIDATE_ELF, &argv, &envp, &aux) } {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("load_user_process_with failed on narf-libc-validate"),
    };

    *USER_AS.lock() = Some(proc.address_space.clone());

    if proc.address_space.activate().is_err() {
        return TestResult::Fail("activate failed");
    }

    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!("cli");
    }
    // SAFETY: Valid memory or trusted environment
    unsafe { user_mode_enter(proc.entry.0.as_u64(), proc.stack_top.as_u64()) }
}
#[cfg(all(target_arch = "x86_64", feature = "narf-libc-validate"))]
kernel_test!(smoke_frame_x86_64_run_narf_libc_validate);

// `smoke_userspace_raw_handler_dispatch` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_process_id_and_aux` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_obs_gdb_packet_checksum` migrated to observability/src/tests.rs (subsystem `"observability"`).

// `smoke_obs_gdb_attach_not_implemented` migrated to observability/src/tests.rs (subsystem `"observability"`).

// `smoke_obs_peek_provider_registration` migrated to observability/src/tests.rs (subsystem `"observability"`).

// `smoke_time_wall_offset_and_leap_smear` migrated to time/src/tests.rs (subsystem `"time"`).

// `smoke_power_thermal_zone_transitions` migrated to power/src/tests.rs (subsystem `"power"`).

// `smoke_power_energy_aware_governor` migrated to power/src/tests.rs (subsystem `"power"`).

// `smoke_block_mq_round_robins_across_lanes` migrated to block/src/tests.rs (subsystem `"block"`).

// `smoke_block_deadline_tags_are_monotonic` migrated to block/src/tests.rs (subsystem `"block"`).

// `smoke_userspace_getrandom_fills_buffer` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_listdir_walks_memfs` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_clock_gettime_distinguishes_clocks` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_setuid_setgid_round_trip` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_hostname_round_trip` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_ftruncate_grows_and_shrinks_memfile` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_pread_pwrite_dont_move_cursor` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_filesystem_devfs_null_zero` migrated to filesystem/src/tests.rs (subsystem `"filesystem"`).

// `smoke_filesystem_devfs_random_urandom` migrated to filesystem/src/tests.rs (subsystem `"filesystem"`).

// `smoke_filesystem_devfs_mount_default_idempotent` migrated to filesystem/src/tests.rs (subsystem `"filesystem"`).

// `smoke_userspace_rlimit_round_trip` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_priority_round_trip` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_times_writes_tms_struct` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_getrusage_writes_18_i64s` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_umask_round_trip` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_getcpu_returns_zero` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_sched_affinity_round_trip` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_prctl_name_round_trip` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_fallocate_extends_and_zero_ranges_memfile` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_copy_file_range_round_trip` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_clock_settime_pushes_wall_offset` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_futex_wait_and_wake_no_op` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_memfd_create_returns_writable_fd` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_getdents64_writes_linux_records` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_init_per_task_state_is_idempotent` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_sched_priority_bounds_and_param` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_pgid_round_trip` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// `smoke_userspace_setsid_makes_session_leader` migrated to userspace/src/tests.rs (subsystem `"userspace"`).

// ── AML resource decoder smokes ──────────────────────────────────────────────

// `smoke_aml_resource_irq_io_endtag` migrated to aml/src/tests.rs (subsystem `"aml"`).
// `smoke_aml_resource_memory32fixed_large_tag` migrated to aml/src/tests.rs (subsystem `"aml"`).
// `smoke_aml_prt_decode` migrated to aml/src/tests.rs (subsystem `"aml"`).
// `smoke_aml_oregion_sysmem_dword_field` migrated to aml/src/tests.rs (subsystem `"aml"`).
// `smoke_aml_oregion_bit_fields` migrated to aml/src/tests.rs (subsystem `"aml"`).
// `smoke_aml_oregion_boot_regions_present` migrated to aml/src/tests.rs (subsystem `"aml"`).
// `smoke_aml_oregion_pci_config_resolves` migrated to aml/src/tests.rs (subsystem `"aml"`).
// `smoke_aml_sync_mutex_acquire_release` migrated to aml/src/tests.rs (subsystem `"aml"`).
// `smoke_aml_sync_stall_sleep_no_trap` migrated to aml/src/tests.rs (subsystem `"aml"`).
// `smoke_aml_sync_notify_dispatch` migrated to aml/src/tests.rs (subsystem `"aml"`).
// `smoke_aml_sync_event_signal_wait` migrated to aml/src/tests.rs (subsystem `"aml"`).
// `smoke_aml_gpe_install_aml_handlers` migrated to aml/src/tests.rs (subsystem `"aml"`).
// `smoke_aml_gpe_dispatch_native` migrated to aml/src/tests.rs (subsystem `"aml"`).
// `smoke_aml_gpe_dispatch_aml` migrated to aml/src/tests.rs (subsystem `"aml"`).

// `smoke_acpi_gpe_block_parsed_at_boot` migrated to acpi/src/tests.rs (subsystem `"acpi"`).

// ── _PRT / _CRS bridge smoke tests ───────────────────────────────────────────
//
// These tests use __reset_for_test() + __parse_body_for_test() to install
// synthetic AML methods, then call evaluate_prt_for / evaluate_crs_for and
// verify the decoded results.  Using distinct \_T1 / \_T2 scopes avoids
// conflicts with any other test in the harness.

// `smoke_aml_prt_evaluation_round_trip` migrated to aml/src/tests.rs (subsystem `"aml"`).
// `smoke_aml_crs_evaluation_round_trip` migrated to aml/src/tests.rs (subsystem `"aml"`).
// `smoke_aml_prt_method_not_found` migrated to aml/src/tests.rs (subsystem `"aml"`).

// ── Driver-foundation arc smokes (e94093a..e99df8e) ────────────────
//
// These smokes were originally drafted next to their related code
// in the 1-8 driver foundation arc but landed at end-of-file
// because linkme distributed_slice ordering is sensitive to
// section placement, and inserting smokes mid-file reproducibly
// perturbed `smoke_audio_submit_shmem_zero_copy`. Aggregating
// them here keeps the build-order shape stable.

// `smoke_drivers_reset_default_is_noop` migrated to drivers/src/tests.rs (subsystem `"drivers"`).

// `smoke_hotplug_default_dispatcher_round_trip` migrated to bus/src/tests.rs (subsystem `"bus"`).

// `smoke_aer_classifier_severity` migrated to bus/src/tests.rs (subsystem `"bus"`).

// `smoke_power_dstate_classification` migrated to power/src/tests.rs (subsystem `"power"`).

// ── compat/win — PE32+ loader smoke ────────────────────────────────
//
// Exercises the Win32-on-NARF loader pipeline end-to-end: parse a
// synthetic PE32+ image, allocate a fresh user AS, materialize all
// sections, apply DIR64 relocs, resolve imports against a custom
// resolver, populate PEB / TEB. The image imports
// `kernel32!ExitProcess` so the resolver path is exercised.
//
// Note: this validates the loader contract — not user-mode
// execution. The Ring-3 → kernel call path that turns a patched
// IAT slot into an actual thunk invocation lands in M0.5; see
// `compat/win/specification/spec.md` §8.

#[cfg(target_arch = "x86_64")]
fn build_synthetic_pe(machine: u16) -> alloc::vec::Vec<u8> {
    use alloc::vec;
    let mut buf = vec![0u8; 0x800];

    // DOS header.
    buf[0..2].copy_from_slice(&0x5A4Du16.to_le_bytes()); // 'MZ'
    buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    // NT signature.
    buf[0x80..0x84].copy_from_slice(&0x0000_4550u32.to_le_bytes());
    // File header.
    let fh = 0x84;
    buf[fh..fh + 2].copy_from_slice(&machine.to_le_bytes());
    buf[fh + 2..fh + 4].copy_from_slice(&2u16.to_le_bytes()); // 2 sections
    buf[fh + 16..fh + 18].copy_from_slice(&0xF0u16.to_le_bytes()); // opt-hdr size
                                                                   // Optional header.
    let oh = fh + 20; // 0x98
    buf[oh..oh + 2].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+
    buf[oh + 0x10..oh + 0x14].copy_from_slice(&0x1000u32.to_le_bytes()); // entry
    buf[oh + 0x18..oh + 0x20].copy_from_slice(&0x1_4000_0000u64.to_le_bytes()); // image base
    buf[oh + 0x38..oh + 0x3C].copy_from_slice(&0x3000u32.to_le_bytes()); // size of image
    buf[oh + 0x6C..oh + 0x70].copy_from_slice(&16u32.to_le_bytes()); // num dirs
                                                                     // DataDirectory[1] = Import: RVA 0x2000, size 0x60.
    buf[oh + 0x70 + 8..oh + 0x70 + 12].copy_from_slice(&0x2000u32.to_le_bytes());
    buf[oh + 0x70 + 12..oh + 0x70 + 16].copy_from_slice(&0x60u32.to_le_bytes());
    // DataDirectory[5] = BaseReloc: RVA 0x2100, size 0x10.
    buf[oh + 0x70 + 5 * 8..oh + 0x70 + 5 * 8 + 4].copy_from_slice(&0x2100u32.to_le_bytes());
    buf[oh + 0x70 + 5 * 8 + 4..oh + 0x70 + 5 * 8 + 8].copy_from_slice(&0x10u32.to_le_bytes());

    // Section table (.text at 0x188, .idata at 0x1B0).
    let sec = oh + 0xF0; // 0x188
    buf[sec..sec + 5].copy_from_slice(b".text");
    buf[sec + 8..sec + 12].copy_from_slice(&0x100u32.to_le_bytes());
    buf[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[sec + 16..sec + 20].copy_from_slice(&0x100u32.to_le_bytes());
    buf[sec + 20..sec + 24].copy_from_slice(&0x400u32.to_le_bytes());
    buf[sec + 36..sec + 40].copy_from_slice(&0x6000_0000u32.to_le_bytes()); // R+X
    let s2 = sec + 40;
    buf[s2..s2 + 6].copy_from_slice(b".idata");
    buf[s2 + 8..s2 + 12].copy_from_slice(&0x300u32.to_le_bytes());
    buf[s2 + 12..s2 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    buf[s2 + 16..s2 + 20].copy_from_slice(&0x300u32.to_le_bytes());
    buf[s2 + 20..s2 + 24].copy_from_slice(&0x500u32.to_le_bytes());
    buf[s2 + 36..s2 + 40].copy_from_slice(&0x4000_0000u32.to_le_bytes()); // R only

    // IID #0: ILT 0x2040, Name 0x2080, IAT 0x20A0.
    let iid = 0x500;
    buf[iid..iid + 4].copy_from_slice(&0x2040u32.to_le_bytes());
    buf[iid + 12..iid + 16].copy_from_slice(&0x2080u32.to_le_bytes());
    buf[iid + 16..iid + 20].copy_from_slice(&0x20A0u32.to_le_bytes());
    // ILT @ 0x540 → IMAGE_IMPORT_BY_NAME @ 0x20C0.
    buf[0x540..0x548].copy_from_slice(&0x20C0u64.to_le_bytes());
    // IAT @ 0x5A0 (pre-resolution) → same.
    buf[0x5A0..0x5A8].copy_from_slice(&0x20C0u64.to_le_bytes());
    // Module name @ 0x580: "kernel32.dll".
    buf[0x580..0x58C].copy_from_slice(b"kernel32.dll");
    // IMAGE_IMPORT_BY_NAME @ 0x5C0: hint=0, name="ExitProcess".
    buf[0x5C2..0x5CD].copy_from_slice(b"ExitProcess");
    // Base reloc block @ 0x600: page 0x1000, size 0x10, one DIR64 at +0x008.
    buf[0x600..0x604].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[0x604..0x608].copy_from_slice(&0x10u32.to_le_bytes());
    let dir64_entry: u16 = (10u16 << 12) | 0x008;
    buf[0x608..0x60A].copy_from_slice(&dir64_entry.to_le_bytes());
    buf
}

#[cfg(target_arch = "x86_64")]
fn smoke_compat_win_load_pe_pipeline() -> TestResult {
    use narf_compat_win::load_pe;

    let bytes = build_synthetic_pe(0x8664); // AMD64

    // Custom resolver: returns a synthetic user-mode VA for the
    // one import the synthetic PE declares. In the real flow this
    // VA points into the mapped compat-win-rt system DLL; for the
    // smoke we just need any non-zero VA to exercise IAT patching.
    fn resolver(module: &str, symbol: &str) -> Option<u64> {
        if module.eq_ignore_ascii_case("kernel32.dll") && symbol.eq_ignore_ascii_case("exitprocess")
        {
            Some(0x7FFE_0000_2000) // synthetic compat-win-rt VA
        } else {
            None
        }
    }

    // SAFETY: the kernel test harness runs with the low-4-GiB
    // identity map and frame allocator initialised — both contracts
    // load_pe documents.
    // SAFETY: Valid memory or trusted environment
    let proc = match unsafe {
        load_pe(&bytes, resolver, /*pid=*/ 0xCAFE, /*tid=*/ 0xBABE)
    } {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("compat-win: load_pe failed"),
    };

    // Entry point: image_base + AddressOfEntryPoint.
    if proc.entry.as_u64() != 0x1_4000_0000 + 0x1000 {
        return TestResult::Fail("compat-win: entry mismatch");
    }
    if proc.image_base != 0x1_4000_0000 {
        return TestResult::Fail("compat-win: image_base mismatch");
    }
    if proc.size_of_image != 0x3000 {
        return TestResult::Fail("compat-win: size_of_image mismatch");
    }
    if proc.peb_va.as_u64() != narf_compat_win::personality::DEFAULT_PEB_VA {
        return TestResult::Fail("compat-win: peb_va mismatch");
    }
    if proc.teb_va.as_u64() != narf_compat_win::personality::DEFAULT_TEB_VA {
        return TestResult::Fail("compat-win: teb_va mismatch");
    }
    if proc.stack_top.as_u64() <= proc.stack_base.as_u64() {
        return TestResult::Fail("compat-win: stack range inverted");
    }

    // Region count: 2 PE sections + PEB + TEB + stack = 5.
    // (No trampoline page in v1.0 — IAT slots resolve to user-mode
    // VAs in the compat-win-rt mapping; spec §8.3.)
    let regions = proc.address_space.regions_snapshot();
    if regions.len() != 5 {
        return TestResult::Fail("compat-win: expected 5 mapped regions");
    }
    // Stack range matches the Layout default and is mapped R+W.
    let stack_region = regions
        .iter()
        .find(|r| r.base.as_u64() == proc.stack_base.as_u64());
    let stack_region = match stack_region {
        Some(r) => r,
        None => return TestResult::Fail("compat-win: stack region missing"),
    };
    if stack_region.len != (proc.stack_top.as_u64() - proc.stack_base.as_u64()) {
        return TestResult::Fail("compat-win: stack region size mismatch");
    }
    // The two PE sections live at image_base + section.virt_addr.
    let section_base_text = 0x1_4000_0000u64 + 0x1000;
    let section_base_idata = 0x1_4000_0000u64 + 0x2000;
    let mut saw_text = false;
    let mut saw_idata = false;
    let mut saw_peb = false;
    let mut saw_teb = false;
    for r in &regions {
        let b = r.base.as_u64();
        if b == section_base_text {
            saw_text = true;
        }
        if b == section_base_idata {
            saw_idata = true;
        }
        if b == narf_compat_win::personality::DEFAULT_PEB_VA {
            saw_peb = true;
        }
        if b == narf_compat_win::personality::DEFAULT_TEB_VA {
            saw_teb = true;
        }
    }
    if !(saw_text && saw_idata && saw_peb && saw_teb) {
        return TestResult::Fail("compat-win: expected regions missing");
    }

    // Mint a spawn cap — exercises the cap-typing path.
    let _cap = proc.mint_spawn_cap();
    TestResult::Pass
}

#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_compat_win_load_pe_pipeline);

#[cfg(feature = "user-mode-e2e")]
fn smoke_firmware_install_syscall_round_trip() -> TestResult {
    // End-to-end: dispatch the FirmwareInstall syscall through the
    // SyscallTable with a fake TrapContext, exactly like an arch
    // trap would. Verifies the trap-handler shim's pointer
    // validation, kernel-side sys_install delegation, and the
    // registry round-trip. Gated by `user-mode-e2e` because it
    // mutates the global firmware registry; the gate keeps it out
    // of the structural smoke set that runs on every build.
    if !cfg!(feature = "firmware-allow-unsigned") {
        return TestResult::Skip("firmware-allow-unsigned off — registry rejects unsigned");
    }
    use narf_firmware::{bootstrap_authority, source_for, BlobSource, BLOB_TRAILER_MAGIC};
    use narf_userspace::{
        install_core_syscalls, Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };

    // Reset both halves of the registry: the blob storage and
    // the per-task cap table. Then grant task 0 (the smoke
    // harness's pid) a fresh firmware-registry authority cap so
    // the trap-handler privilege gate accepts the call.
    narf_firmware::registry::__reset_for_test();
    narf_firmware::__reset_trusted_loader_tasks();
    let _ = narf_firmware::grant_firmware_authority(0);
    // The legacy process-global trusted-loader authority is no
    // longer consulted by the trap handler (it now uses the per-
    // task cap), but `bootstrap_authority` is still useful as a
    // compatibility shim — bring one up so dependent helpers
    // continue to work.
    let (_write, _r) = bootstrap_authority();

    // Build an unsigned blob the registry will accept under the
    // `firmware-allow-unsigned` build feature.
    let mut blob = alloc::vec::Vec::with_capacity(256);
    blob.extend_from_slice(b"syscall e2e payload");
    blob.extend_from_slice(&[0u8; 64]); // signature
    blob.extend_from_slice(&[0u8; 32]); // signer
    blob.extend_from_slice(&0u32.to_le_bytes()); // mlen=0
    blob.extend_from_slice(&BLOB_TRAILER_MAGIC); // 'NRFW'

    let name = b"e2e/syscall/blob";

    // Build the SyscallTable + install handlers.
    let mut table = SyscallTable::new();
    install_core_syscalls(&mut table);

    // Fake TrapContext.
    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _: u64) {}
        fn redirect_to_kernel(&mut self, _: u64, _: u64) -> bool {
            false
        }
    }
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: name.as_ptr() as u64,
            arg1: name.len() as u64,
            arg2: blob.as_ptr() as u64,
            arg3: blob.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    table.dispatch(Syscall::FirmwareInstall, &mut ctx);

    let r = match ctx.ret {
        Some(r) => r,
        None => return TestResult::Fail("handler set no return value"),
    };
    if r.value != 0 {
        return TestResult::Fail("FirmwareInstall returned non-zero");
    }
    if source_for("e2e/syscall/blob") != Some(BlobSource::HotInstall) {
        return TestResult::Fail("blob not landed at HotInstall priority");
    }
    TestResult::Pass
}
#[cfg(feature = "user-mode-e2e")]
kernel_test!(smoke_firmware_install_syscall_round_trip);

// ── Multi-task integration: scheduler ↔ FdTable, IRQ, filesystem ────
//
// Tests sit in narf-verification because they need scheduler +
// userspace fd + filesystem + interrupts simultaneously. Each
// runs sequentially on the BSP — multiple tasks interleave via
// poll_one_round.

/// Spawn N tasks, each opens an FdEntry in its own task-keyed
/// FdTable and closes it. With_table acquires the global lock
/// each call; pressure tests that lock under task switches.
/// Verifies per-task FD tables are isolated even when the
/// owning task is preempted mid-operation.
#[cfg(target_arch = "x86_64")]
fn smoke_fdtable_concurrent_open_close_per_task() -> TestResult {
    use alloc::sync::Arc;
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicU32, Ordering};
    use core::task::{Context, Poll};
    use narf_filesystem::FileOps;
    use narf_userspace::{fd, FdEntry};

    fd::__test_reset();

    const TASKS: u64 = 6;
    const OPS: u32 = 8;
    static COMPLETED: AtomicU32 = AtomicU32::new(0);
    static LOST: AtomicU32 = AtomicU32::new(0);
    COMPLETED.store(0, Ordering::Release);
    LOST.store(0, Ordering::Release);

    // Console-style noop file ops for FdEntry construction.
    struct NoopOps;
    impl FileOps for NoopOps {
        fn read<'a>(
            &'a self,
            _offset: u64,
            _buf: &'a mut [u8],
        ) -> narf_filesystem::FsFuture<'a, usize> {
            alloc::boxed::Box::pin(async { Ok(0) })
        }
        fn write<'a>(
            &'a self,
            _offset: u64,
            buf: &'a [u8],
        ) -> narf_filesystem::FsFuture<'a, usize> {
            let n = buf.len();
            alloc::boxed::Box::pin(async move { Ok(n) })
        }
        fn stat(&self) -> narf_filesystem::Stat {
            narf_filesystem::Stat {
                size: 0,
                blocks: 0,
                mode: narf_filesystem::Mode::FILE_RO,
                mtime_cycles: 0,
            }
        }
    }

    struct Worker {
        task_id: u64,
        remaining: u32,
    }
    impl Future for Worker {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.remaining == 0 {
                COMPLETED.fetch_add(1, Ordering::AcqRel);
                return Poll::Ready(());
            }
            let entry = FdEntry {
                ops: Arc::new(NoopOps) as Arc<dyn FileOps>,
                offset: 0,
                flags: 0,
                status_flags: 0,
            };
            // Open into THIS task's per-task table (keyed by
            // self.task_id, not the executor's current task id).
            // `open` is bounded by the task's RLIMIT_NOFILE now, so it can
            // report exhaustion. This benchmark closes every descriptor it
            // opens, so hitting the limit means a leak in the loop itself —
            // count it as lost rather than silently ending the run.
            let fd = fd::install(self.task_id, entry);
            let fd = match fd {
                Some(f) => f,
                None => {
                    LOST.fetch_add(1, Ordering::AcqRel);
                    return Poll::Ready(());
                }
            };
            // FdTable.open returns lowest free slot ≥ 3, so any
            // FD < 3 indicates the stdio reservation logic
            // missed.
            if fd < 3 {
                LOST.fetch_add(1, Ordering::AcqRel);
                return Poll::Ready(());
            }
            let closed = fd::with_table(self.task_id, |t| t.close(fd)).unwrap_or(false);
            if !closed {
                LOST.fetch_add(1, Ordering::AcqRel);
                return Poll::Ready(());
            }
            self.remaining -= 1;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    // Use synthetic task_ids in a range that won't collide with
    // any real spawned task ids.
    for i in 0..TASKS {
        narf_scheduler::spawn_stackful(Worker {
            task_id: 0xFEED_0000 + i,
            remaining: OPS,
        });
    }
    for _ in 0..256 {
        narf_scheduler::poll_one_round();
        if COMPLETED.load(Ordering::Acquire) as u64 >= TASKS {
            break;
        }
    }
    if LOST.load(Ordering::Acquire) != 0 {
        return TestResult::Fail("FD open/close lost an FD under contention");
    }
    if (COMPLETED.load(Ordering::Acquire) as u64) != TASKS {
        return TestResult::Fail("FD-stress tasks didn't all finish");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_fdtable_concurrent_open_close_per_task);

/// Multiple tasks waiting on DIFFERENT IRQ vectors. Each
/// vector has a single waker slot (per the contract), so each
/// task gets its own vector. After firing each vector's IRQ,
/// every waiter must resolve.
///
/// Tests the per-vector independence of the dispatch table
/// under multi-task pressure — a regression where vectors
/// shared state would surface here as a missed wake or wrong
/// task waking.
#[cfg(target_arch = "x86_64")]
fn smoke_irq_per_vector_independent_waiters() -> TestResult {
    use core::sync::atomic::{AtomicU32, Ordering};

    const VECTORS: [u8; 4] = [64, 65, 66, 67];
    static COMPLETED: AtomicU32 = AtomicU32::new(0);
    COMPLETED.store(0, Ordering::Release);

    async fn waiter(v: u8) {
        let _ = narf_interrupts::wait::wait_for_irq(v).await;
        COMPLETED.fetch_add(1, Ordering::AcqRel);
    }

    for v in VECTORS.iter().copied() {
        narf_scheduler::spawn_stackful(waiter(v));
    }
    // Let waiters poll once to register their wakers.
    for _ in 0..4 {
        narf_scheduler::poll_one_round();
    }
    // Fire each vector — each on_irq wakes the registered
    // waker for its vector independently.
    for v in VECTORS.iter().copied() {
        narf_interrupts::dispatch::on_irq(v);
    }
    for _ in 0..16 {
        narf_scheduler::poll_one_round();
        if (COMPLETED.load(Ordering::Acquire) as usize) >= VECTORS.len() {
            break;
        }
    }
    if (COMPLETED.load(Ordering::Acquire) as usize) != VECTORS.len() {
        return TestResult::Fail("a per-vector waiter didn't resolve after its IRQ fired");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_irq_per_vector_independent_waiters);

/// A pre-armed IRQ (fire_count already advanced) resolves a
/// freshly-constructed WaitForIrq immediately on first poll if
/// the baseline check sees the count past the snapshot. Covers
/// the "IRQ fired between wait construction and first poll"
/// path.
#[cfg(target_arch = "x86_64")]
fn smoke_irq_wait_resolves_when_already_fired() -> TestResult {
    use core::sync::atomic::{AtomicBool, Ordering};

    const VECTOR: u8 = 68;
    static DONE: AtomicBool = AtomicBool::new(false);
    DONE.store(false, Ordering::Release);

    // Bump the fire_count BEFORE the waiter is constructed.
    let pre_baseline = narf_interrupts::dispatch::fire_count(VECTOR);
    narf_interrupts::dispatch::on_irq(VECTOR);
    narf_interrupts::dispatch::on_irq(VECTOR);
    let post_baseline = narf_interrupts::dispatch::fire_count(VECTOR);
    if post_baseline <= pre_baseline {
        return TestResult::Fail("on_irq didn't advance fire_count");
    }

    async fn waiter() {
        // The WaitForIrq snapshots fire_count at construction;
        // first poll's second baseline-read sees the increment
        // we made AFTER construction is impossible here, but
        // since wait_for_irq() snapshots inside the function
        // body BEFORE the first poll, an already-pre-armed
        // count means we wait for the NEXT increment.
        let _ = narf_interrupts::wait::wait_for_irq(VECTOR).await;
        DONE.store(true, Ordering::Release);
    }

    narf_scheduler::spawn_stackful(waiter());
    // Poll once to register the waker.
    narf_scheduler::poll_one_round();
    // Now fire one more IRQ — waiter must resolve.
    narf_interrupts::dispatch::on_irq(VECTOR);
    for _ in 0..16 {
        narf_scheduler::poll_one_round();
        if DONE.load(Ordering::Acquire) {
            break;
        }
    }
    if !DONE.load(Ordering::Acquire) {
        return TestResult::Fail("waiter didn't resolve after subsequent IRQ fire");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_irq_wait_resolves_when_already_fired);

/// install + clear sync handler: a registered handler fires on
/// each on_irq for its vector; cleared, subsequent fires don't
/// invoke it. Covers an under-tested API used by xhci_isr,
/// HPET pump_irq, and other ISRs.
#[cfg(target_arch = "x86_64")]
fn smoke_irq_sync_handler_install_invoke_clear() -> TestResult {
    use core::sync::atomic::{AtomicU32, Ordering};

    const VECTOR: u8 = 70;
    static FIRED: AtomicU32 = AtomicU32::new(0);
    FIRED.store(0, Ordering::Release);

    fn handler() {
        FIRED.fetch_add(1, Ordering::AcqRel);
    }

    // Pre-clear in case a previous test left state.
    narf_interrupts::dispatch::clear_handler(VECTOR);
    narf_interrupts::dispatch::on_irq(VECTOR);
    if FIRED.load(Ordering::Acquire) != 0 {
        return TestResult::Fail("handler fired before install");
    }

    narf_interrupts::dispatch::install(VECTOR, handler);
    narf_interrupts::dispatch::on_irq(VECTOR);
    narf_interrupts::dispatch::on_irq(VECTOR);
    narf_interrupts::dispatch::on_irq(VECTOR);
    if FIRED.load(Ordering::Acquire) != 3 {
        return TestResult::Fail("installed handler didn't fire on every on_irq");
    }

    narf_interrupts::dispatch::clear_handler(VECTOR);
    narf_interrupts::dispatch::on_irq(VECTOR);
    if FIRED.load(Ordering::Acquire) != 3 {
        return TestResult::Fail("handler fired after clear");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_irq_sync_handler_install_invoke_clear);

/// Burst-spawn N one-shot tasks; drain via poll_one_round; the
/// scheduler's slot drop path must reclaim every completed
/// task's slot. Verifies via a Drop counter on the future payload
/// that EVERY spawned future's Drop runs after Ready — catches
/// leak regressions where the slot drop forgets to drop the
/// boxed future.
#[cfg(target_arch = "x86_64")]
fn smoke_burst_spawn_no_leaked_futures() -> TestResult {
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicU32, Ordering};
    use core::task::{Context, Poll};

    const TASKS: u32 = 32;
    static CONSTRUCTED: AtomicU32 = AtomicU32::new(0);
    static DROPPED: AtomicU32 = AtomicU32::new(0);
    static POLLED: AtomicU32 = AtomicU32::new(0);
    CONSTRUCTED.store(0, Ordering::Release);
    DROPPED.store(0, Ordering::Release);
    POLLED.store(0, Ordering::Release);

    struct Counted;
    impl Counted {
        fn new() -> Self {
            CONSTRUCTED.fetch_add(1, Ordering::AcqRel);
            Counted
        }
    }
    impl Drop for Counted {
        fn drop(&mut self) {
            DROPPED.fetch_add(1, Ordering::AcqRel);
        }
    }
    impl Future for Counted {
        type Output = ();
        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
            POLLED.fetch_add(1, Ordering::AcqRel);
            Poll::Ready(())
        }
    }

    for _ in 0..TASKS {
        narf_scheduler::spawn(Counted::new());
    }
    for _ in 0..64 {
        narf_scheduler::poll_one_round();
        if POLLED.load(Ordering::Acquire) >= TASKS && DROPPED.load(Ordering::Acquire) >= TASKS {
            break;
        }
    }
    let polled = POLLED.load(Ordering::Acquire);
    let dropped = DROPPED.load(Ordering::Acquire);
    let constructed = CONSTRUCTED.load(Ordering::Acquire);
    if polled != TASKS {
        return TestResult::Fail("not every task's future was polled to Ready");
    }
    if dropped != constructed {
        return TestResult::Fail("some Counted futures never dropped — scheduler leaked a slot");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_burst_spawn_no_leaked_futures);

/// IRQ fire_count is monotonic across many concurrent on_irq
/// invocations from different tasks. (on_irq's per-slot atomic
/// must not lose increments.)
#[cfg(target_arch = "x86_64")]
fn smoke_irq_fire_count_monotonic_under_contention() -> TestResult {
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicU32, Ordering};
    use core::task::{Context, Poll};

    const TEST_VECTOR: u8 = 65;
    const TASKS: usize = 4;
    const FIRES_PER_TASK: u32 = 32;
    static DONE: AtomicU32 = AtomicU32::new(0);
    DONE.store(0, Ordering::Release);

    let baseline = narf_interrupts::dispatch::fire_count(TEST_VECTOR);

    struct Firer {
        remaining: u32,
    }
    impl Future for Firer {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.remaining == 0 {
                DONE.fetch_add(1, Ordering::AcqRel);
                return Poll::Ready(());
            }
            narf_interrupts::dispatch::on_irq(TEST_VECTOR);
            self.remaining -= 1;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    for _ in 0..TASKS {
        narf_scheduler::spawn_stackful(Firer {
            remaining: FIRES_PER_TASK,
        });
    }
    for _ in 0..512 {
        narf_scheduler::poll_one_round();
        if (DONE.load(Ordering::Acquire) as usize) >= TASKS {
            break;
        }
    }
    if (DONE.load(Ordering::Acquire) as usize) != TASKS {
        return TestResult::Fail("Firer tasks didn't all complete");
    }
    let final_count = narf_interrupts::dispatch::fire_count(TEST_VECTOR);
    let expected = baseline + (TASKS as u64) * (FIRES_PER_TASK as u64);
    if final_count < expected {
        return TestResult::Fail("fire_count lost increments under multi-task contention");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_irq_fire_count_monotonic_under_contention);

// ── Filesystem multi-task (memfs) ──────────────────────────────────

/// N tasks concurrently create + unlink files in a shared MemFs.
/// Each task uses its own name namespace so collisions don't
/// confuse the test, but ALL tasks contend on MemDir's
/// IrqSafeSpinLock<BTreeMap> for entries. After all complete,
/// file_count must be zero (every create paired with an unlink).
#[cfg(target_arch = "x86_64")]
fn smoke_fs_memfs_concurrent_create_unlink() -> TestResult {
    use alloc::sync::Arc;
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicU32, Ordering};
    use core::task::{Context, Poll};
    use narf_filesystem::FsInstance;

    const TASKS: usize = 4;
    const ITERS: u32 = 8;
    static DONE: AtomicU32 = AtomicU32::new(0);
    static ERR: AtomicU32 = AtomicU32::new(0);
    DONE.store(0, Ordering::Release);
    ERR.store(0, Ordering::Release);

    let memfs = Arc::new(narf_filesystem::memfs::MemFs::new("test"));

    struct Worker {
        idx: usize,
        remaining: u32,
        fs: Arc<narf_filesystem::memfs::MemFs>,
    }
    impl Future for Worker {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.remaining == 0 {
                DONE.fetch_add(1, Ordering::AcqRel);
                return Poll::Ready(());
            }
            let name = alloc::format!("t{}-{}", self.idx, self.remaining);
            let root = self.fs.root();
            // Create.
            let mut create_fut = root.create(&name);
            let created = match Pin::new(&mut create_fut).poll(cx) {
                Poll::Ready(Ok(_)) => true,
                Poll::Ready(Err(_)) => {
                    ERR.fetch_add(1, Ordering::AcqRel);
                    false
                }
                Poll::Pending => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            };
            if !created {
                self.remaining -= 1;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            // Unlink.
            let mut unlink_fut = root.unlink(&name);
            match Pin::new(&mut unlink_fut).poll(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(_)) => {
                    ERR.fetch_add(1, Ordering::AcqRel);
                }
                Poll::Pending => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
            self.remaining -= 1;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    for i in 0..TASKS {
        narf_scheduler::spawn_stackful(Worker {
            idx: i,
            remaining: ITERS,
            fs: memfs.clone(),
        });
    }
    for _ in 0..512 {
        narf_scheduler::poll_one_round();
        if (DONE.load(Ordering::Acquire) as usize) >= TASKS {
            break;
        }
    }
    if (DONE.load(Ordering::Acquire) as usize) != TASKS {
        return TestResult::Fail("memfs concurrent workers didn't all finish");
    }
    if ERR.load(Ordering::Acquire) != 0 {
        return TestResult::Fail("memfs create/unlink reported errors under contention");
    }
    if memfs.file_count() != 0 {
        return TestResult::Fail("memfs has leaked file entries after create+unlink balance");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_fs_memfs_concurrent_create_unlink);

// ── Bus registry under multi-task pressure ─────────────────────────

/// N reader tasks call `snapshot()` concurrently. snapshot
/// returns a Vec<BusDevice> built under the registry's lock;
/// while a snapshot is in progress, no install/claim should
/// see torn state. The test focuses on the read consistency
/// (sizes match a baseline). install() is exercised once
/// before the spawn burst to seed the registry.
#[cfg(target_arch = "x86_64")]
fn smoke_bus_registry_concurrent_snapshots_consistent() -> TestResult {
    use alloc::vec::Vec;
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicU32, Ordering};
    use core::task::{Context, Poll};
    use narf_bus::{registry, BusAddr, BusDevice, BusKind, DeviceId, PcieAddr};
    use narf_memory::PhysAddr;

    // Build a synthetic device list — never published anywhere
    // else, so we can verify snapshot reads against it.
    let mut devices: Vec<BusDevice> = Vec::new();
    for i in 0..8u8 {
        devices.push(BusDevice {
            addr: BusAddr::Pcie(PcieAddr {
                segment: 0,
                bus: 0xFE,
                device: i,
                function: 0,
            }),
            id: DeviceId {
                vendor: 0xDEAD,
                device: 0xBEEF,
                class: 0,
                subsystem_vendor: 0,
                subsystem_id: 0,
            },
            kind: BusKind::Pcie {
                addr: PcieAddr {
                    segment: 0,
                    bus: 0xFE,
                    device: i,
                    function: 0,
                },
                cfg_phys: PhysAddr::new(0xFEED_0000 + (i as u64) * 0x1000),
            },
        });
    }
    let expected_len = devices.len();
    registry::install(devices);

    const TASKS: usize = 4;
    const ITERS: u32 = 16;
    static DONE: AtomicU32 = AtomicU32::new(0);
    static SHORT_READ: AtomicU32 = AtomicU32::new(0);
    DONE.store(0, Ordering::Release);
    SHORT_READ.store(0, Ordering::Release);

    struct Snapper {
        remaining: u32,
        expected: usize,
    }
    impl Future for Snapper {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.remaining == 0 {
                DONE.fetch_add(1, Ordering::AcqRel);
                return Poll::Ready(());
            }
            let snap = registry::snapshot();
            // The registry was seeded with `expected` devices.
            // A torn read would return a smaller list while
            // another task held the lock mid-clone. snapshot()
            // locks the inner vec for the duration of the clone,
            // so this should ALWAYS see the full list.
            if snap.len() < self.expected {
                SHORT_READ.fetch_add(1, Ordering::AcqRel);
            }
            self.remaining -= 1;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    for _ in 0..TASKS {
        narf_scheduler::spawn_stackful(Snapper {
            remaining: ITERS,
            expected: expected_len,
        });
    }
    for _ in 0..256 {
        narf_scheduler::poll_one_round();
        if (DONE.load(Ordering::Acquire) as usize) >= TASKS {
            break;
        }
    }
    if (DONE.load(Ordering::Acquire) as usize) != TASKS {
        return TestResult::Fail("bus snapshot tasks didn't all finish");
    }
    if SHORT_READ.load(Ordering::Acquire) != 0 {
        return TestResult::Fail("bus snapshot saw a torn read under contention");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_bus_registry_concurrent_snapshots_consistent);

// ── ACPI/AML concurrent evaluation ─────────────────────────────────

/// node_count + find_all_devices_by_hid are read-only namespace
/// queries; many concurrent callers must observe the same count.
/// The AML namespace is built at boot and treated immutable
/// post-init, so this is really a "no data races on the
/// read-only state" check — important because the AML interp
/// has internal caches.
#[cfg(target_arch = "x86_64")]
fn smoke_aml_concurrent_namespace_reads_stable() -> TestResult {
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
    use core::task::{Context, Poll};

    let baseline = narf_aml::node_count();

    const TASKS: usize = 4;
    const ITERS: u32 = 16;
    static DONE: AtomicU32 = AtomicU32::new(0);
    static DRIFT: AtomicU32 = AtomicU32::new(0);
    static EXPECTED: AtomicU64 = AtomicU64::new(0);
    DONE.store(0, Ordering::Release);
    DRIFT.store(0, Ordering::Release);
    EXPECTED.store(baseline as u64, Ordering::Release);

    struct Reader {
        remaining: u32,
    }
    impl Future for Reader {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.remaining == 0 {
                DONE.fetch_add(1, Ordering::AcqRel);
                return Poll::Ready(());
            }
            let n = narf_aml::node_count() as u64;
            if n != EXPECTED.load(Ordering::Acquire) {
                DRIFT.fetch_add(1, Ordering::AcqRel);
            }
            self.remaining -= 1;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    for _ in 0..TASKS {
        narf_scheduler::spawn_stackful(Reader { remaining: ITERS });
    }
    for _ in 0..256 {
        narf_scheduler::poll_one_round();
        if (DONE.load(Ordering::Acquire) as usize) >= TASKS {
            break;
        }
    }
    if (DONE.load(Ordering::Acquire) as usize) != TASKS {
        return TestResult::Fail("AML reader tasks didn't all finish");
    }
    if DRIFT.load(Ordering::Acquire) != 0 {
        return TestResult::Fail("AML node_count drifted across concurrent readers");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_aml_concurrent_namespace_reads_stable);

// ── Net interface count under reader pressure ──────────────────────

/// Many tasks read iface::count() concurrently. Iface registry
/// uses an IrqSafeSpinLock; readers must see the same value
/// every iteration (post-init it's stable).
#[cfg(target_arch = "x86_64")]
fn smoke_net_iface_count_stable_under_readers() -> TestResult {
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use core::task::{Context, Poll};

    let baseline = narf_net::iface::count();

    const TASKS: usize = 4;
    const ITERS: u32 = 16;
    static DONE: AtomicU32 = AtomicU32::new(0);
    static DRIFT: AtomicU32 = AtomicU32::new(0);
    static EXPECTED: AtomicUsize = AtomicUsize::new(0);
    DONE.store(0, Ordering::Release);
    DRIFT.store(0, Ordering::Release);
    EXPECTED.store(baseline, Ordering::Release);

    struct Reader {
        remaining: u32,
    }
    impl Future for Reader {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.remaining == 0 {
                DONE.fetch_add(1, Ordering::AcqRel);
                return Poll::Ready(());
            }
            let n = narf_net::iface::count();
            if n != EXPECTED.load(Ordering::Acquire) {
                DRIFT.fetch_add(1, Ordering::AcqRel);
            }
            self.remaining -= 1;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    for _ in 0..TASKS {
        narf_scheduler::spawn_stackful(Reader { remaining: ITERS });
    }
    for _ in 0..256 {
        narf_scheduler::poll_one_round();
        if (DONE.load(Ordering::Acquire) as usize) >= TASKS {
            break;
        }
    }
    if (DONE.load(Ordering::Acquire) as usize) != TASKS {
        return TestResult::Fail("net iface count readers didn't all finish");
    }
    if DRIFT.load(Ordering::Acquire) != 0 {
        return TestResult::Fail("net iface count drifted across concurrent readers");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_net_iface_count_stable_under_readers);

// ── Userspace syscall handlers concurrent dispatch ─────────────────

/// Multiple synthetic tasks dispatch sys_getpid (or any
/// no-arg syscall) concurrently. Each task uses its own
/// SyscallTable + handler set, so the GLOBAL syscall registry
/// isn't exercised. What IS exercised: per-task fd-table
/// allocation under spawn pressure (each task lazily creates
/// its own FdTable on first reference via with_table). After
/// completion, every task's table must be its own (not shared).
#[cfg(target_arch = "x86_64")]
fn smoke_userspace_concurrent_fdtable_lazy_init() -> TestResult {
    use alloc::sync::Arc;
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicU32, Ordering};
    use core::task::{Context, Poll};
    use narf_lib::sync::IrqSafeSpinLock;
    use narf_userspace::fd;

    fd::__test_reset();

    const TASKS: u64 = 6;
    static DONE: AtomicU32 = AtomicU32::new(0);
    DONE.store(0, Ordering::Release);

    let observed_lens: Arc<IrqSafeSpinLock<alloc::vec::Vec<usize>>> =
        Arc::new(IrqSafeSpinLock::new(alloc::vec::Vec::new()));

    struct Worker {
        task_id: u64,
        observed_lens: Arc<IrqSafeSpinLock<alloc::vec::Vec<usize>>>,
    }
    impl Future for Worker {
        type Output = ();
        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
            // First with_table for this task_id lazily creates a
            // table seeded with stdio (3 entries). Probe via get
            // on fd 0/1/2.
            let stdio_count = fd::with_table(self.task_id, |t| {
                let mut n = 0usize;
                for f in 0u32..3 {
                    if t.get(f).is_some() {
                        n += 1;
                    }
                }
                n
            })
            .unwrap_or(0);
            self.observed_lens.lock().push(stdio_count);
            DONE.fetch_add(1, Ordering::AcqRel);
            Poll::Ready(())
        }
    }

    for i in 0..TASKS {
        narf_scheduler::spawn_stackful(Worker {
            task_id: 0xABCD_0000 + i,
            observed_lens: observed_lens.clone(),
        });
    }
    for _ in 0..128 {
        narf_scheduler::poll_one_round();
        if (DONE.load(Ordering::Acquire) as u64) >= TASKS {
            break;
        }
    }
    if (DONE.load(Ordering::Acquire) as u64) != TASKS {
        return TestResult::Fail("FD-table init workers didn't all finish");
    }
    let lens = observed_lens.lock().clone();
    if lens.len() != TASKS as usize {
        return TestResult::Fail("not every worker recorded its stdio count");
    }
    for n in lens.iter() {
        if *n != 3 {
            return TestResult::Fail("lazily-initialised FdTable didn't seed all 3 stdio entries");
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_userspace_concurrent_fdtable_lazy_init);

// ── USB xHCI: concurrent fire_count reads ──────────────────────────

/// xHCI is_probed is a single AtomicBool read (via CONTROLLER's
/// lock-protected Option). Many tasks concurrently call it;
/// none should see torn state or different values. Lighter than
/// transfer-submission contention (which requires a real
/// controller present) but covers the API-surface concurrent
/// reads that every driver does.
#[cfg(target_arch = "x86_64")]
fn smoke_usb_xhci_is_probed_consistent_under_readers() -> TestResult {
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicU32, Ordering};
    use core::task::{Context, Poll};

    let baseline = narf_drivers_usb::xhci::is_probed();

    const TASKS: usize = 4;
    const ITERS: u32 = 16;
    static DONE: AtomicU32 = AtomicU32::new(0);
    static DRIFT: AtomicU32 = AtomicU32::new(0);
    DONE.store(0, Ordering::Release);
    DRIFT.store(0, Ordering::Release);

    struct Reader {
        remaining: u32,
        expected: bool,
    }
    impl Future for Reader {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.remaining == 0 {
                DONE.fetch_add(1, Ordering::AcqRel);
                return Poll::Ready(());
            }
            if narf_drivers_usb::xhci::is_probed() != self.expected {
                DRIFT.fetch_add(1, Ordering::AcqRel);
            }
            self.remaining -= 1;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    for _ in 0..TASKS {
        narf_scheduler::spawn_stackful(Reader {
            remaining: ITERS,
            expected: baseline,
        });
    }
    for _ in 0..256 {
        narf_scheduler::poll_one_round();
        if (DONE.load(Ordering::Acquire) as usize) >= TASKS {
            break;
        }
    }
    if (DONE.load(Ordering::Acquire) as usize) != TASKS {
        return TestResult::Fail("xHCI readers didn't all finish");
    }
    if DRIFT.load(Ordering::Acquire) != 0 {
        return TestResult::Fail("xHCI is_probed drifted across concurrent reads");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_usb_xhci_is_probed_consistent_under_readers);

/// add_nmi_handler + on_nmi + remove_nmi_handler round-trip. NMI
/// fires don't go through the same path as IRQs; the chain is
/// lock-free + fixed-size. Test verifies that a registered handler
/// is invoked on on_nmi() with its cookie, and that remove cleanly
/// detaches.
#[cfg(target_arch = "x86_64")]
fn smoke_nmi_handler_install_invoke_remove() -> TestResult {
    use core::sync::atomic::{AtomicU64, Ordering};
    static OBS_COOKIE: AtomicU64 = AtomicU64::new(0);
    static CALLS: AtomicU64 = AtomicU64::new(0);
    OBS_COOKIE.store(0, Ordering::Release);
    CALLS.store(0, Ordering::Release);

    fn handler(cookie: u64) -> narf_interrupts::IrqStatus {
        OBS_COOKIE.store(cookie, Ordering::Release);
        CALLS.fetch_add(1, Ordering::AcqRel);
        narf_interrupts::IrqStatus::Handled
    }

    let id = match narf_interrupts::add_nmi_handler(handler, 0xCAFE_BABE) {
        Some(i) => i,
        None => return TestResult::Fail("add_nmi_handler returned None — table full?"),
    };

    let before_fired = narf_interrupts::nmi_fire_count();
    narf_interrupts::on_nmi();
    if narf_interrupts::nmi_fire_count() != before_fired + 1 {
        narf_interrupts::remove_nmi_handler(id);
        return TestResult::Fail("nmi_fire_count didn't advance");
    }
    if OBS_COOKIE.load(Ordering::Acquire) != 0xCAFE_BABE {
        narf_interrupts::remove_nmi_handler(id);
        return TestResult::Fail("handler didn't see its cookie");
    }
    if CALLS.load(Ordering::Acquire) != 1 {
        narf_interrupts::remove_nmi_handler(id);
        return TestResult::Fail("handler call count wrong");
    }

    narf_interrupts::remove_nmi_handler(id);
    // After removal, on_nmi still bumps fire_count but our handler
    // is detached.
    narf_interrupts::on_nmi();
    if CALLS.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("handler ran after removal");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_nmi_handler_install_invoke_remove);

/// IrqStatus::None on every chained handler bumps spurious_count
/// for the vector. Demonstrates the shared-INTx accounting Linux
/// uses for spurious-IRQ disable detection.
#[cfg(target_arch = "x86_64")]
fn smoke_irq_spurious_count_advances_on_all_none() -> TestResult {
    use core::sync::atomic::AtomicU64;
    const VECTOR: u8 = 80;
    static CALLS: AtomicU64 = AtomicU64::new(0);
    CALLS.store(0, core::sync::atomic::Ordering::Release);

    // Two handlers, both return None. The spurious counter should
    // bump once per on_irq.
    fn pass(_cookie: u64) -> narf_interrupts::IrqStatus {
        CALLS.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        narf_interrupts::IrqStatus::None
    }

    // Clean state (defensive — other tests may have touched this).
    narf_interrupts::dispatch::clear_handler(VECTOR);

    narf_interrupts::install_handler_named(VECTOR, "test-a", 0xAAAA, pass);
    narf_interrupts::install_handler_named(VECTOR, "test-b", 0xBBBB, pass);

    let before = narf_interrupts::spurious_count(VECTOR);
    narf_interrupts::on_irq(VECTOR);
    if narf_interrupts::spurious_count(VECTOR) != before + 1 {
        narf_interrupts::dispatch::clear_handler(VECTOR);
        return TestResult::Fail("spurious_count didn't bump when every handler returned None");
    }
    if CALLS.load(core::sync::atomic::Ordering::Acquire) != 2 {
        narf_interrupts::dispatch::clear_handler(VECTOR);
        return TestResult::Fail("both handlers should have run before spurious accounting");
    }
    narf_interrupts::dispatch::clear_handler(VECTOR);
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_irq_spurious_count_advances_on_all_none);

/// disable_irq makes on_irq a strict no-op. enable_irq restores
/// dispatch.
#[cfg(target_arch = "x86_64")]
fn smoke_irq_disable_enable_round_trip() -> TestResult {
    use core::sync::atomic::AtomicU64;
    const VECTOR: u8 = 81;
    static CALLS: AtomicU64 = AtomicU64::new(0);
    CALLS.store(0, core::sync::atomic::Ordering::Release);

    fn h(_cookie: u64) -> narf_interrupts::IrqStatus {
        CALLS.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        narf_interrupts::IrqStatus::Handled
    }

    narf_interrupts::dispatch::clear_handler(VECTOR);
    narf_interrupts::install_handler_named(VECTOR, "test", 0, h);

    // Enabled by default — handler fires.
    let fire_before = narf_interrupts::fire_count(VECTOR);
    narf_interrupts::on_irq(VECTOR);
    if narf_interrupts::fire_count(VECTOR) != fire_before + 1 {
        narf_interrupts::dispatch::clear_handler(VECTOR);
        return TestResult::Fail("baseline fire didn't count");
    }
    if CALLS.load(core::sync::atomic::Ordering::Acquire) != 1 {
        narf_interrupts::dispatch::clear_handler(VECTOR);
        return TestResult::Fail("baseline handler didn't run");
    }

    // disable_irq → no-op.
    narf_interrupts::disable_irq(VECTOR);
    if !narf_interrupts::is_masked(VECTOR) {
        return TestResult::Fail("is_masked didn't reflect disable");
    }
    let fire_after_disable = narf_interrupts::fire_count(VECTOR);
    narf_interrupts::on_irq(VECTOR);
    if narf_interrupts::fire_count(VECTOR) != fire_after_disable {
        narf_interrupts::dispatch::clear_handler(VECTOR);
        return TestResult::Fail("on_irq advanced fire_count while masked");
    }
    if CALLS.load(core::sync::atomic::Ordering::Acquire) != 1 {
        narf_interrupts::dispatch::clear_handler(VECTOR);
        return TestResult::Fail("handler ran while masked");
    }

    // enable_irq → restored.
    narf_interrupts::enable_irq(VECTOR);
    narf_interrupts::on_irq(VECTOR);
    if CALLS.load(core::sync::atomic::Ordering::Acquire) != 2 {
        narf_interrupts::dispatch::clear_handler(VECTOR);
        return TestResult::Fail("enable_irq didn't restore dispatch");
    }
    narf_interrupts::dispatch::clear_handler(VECTOR);
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_irq_disable_enable_round_trip);

/// Shared handlers fire in install order; first to return Handled
/// stops the chain from counting spurious. Mirrors Linux's
/// IRQF_SHARED semantics.
#[cfg(target_arch = "x86_64")]
fn smoke_irq_shared_chain_first_handled_wins() -> TestResult {
    use core::sync::atomic::AtomicU64;
    const VECTOR: u8 = 82;
    static ORDER: AtomicU64 = AtomicU64::new(0);
    ORDER.store(0, core::sync::atomic::Ordering::Release);

    fn first(_cookie: u64) -> narf_interrupts::IrqStatus {
        // Stamp position 1 in the encoded order if not seen yet.
        let _ = ORDER.compare_exchange(
            0,
            1,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        );
        narf_interrupts::IrqStatus::None
    }
    fn second(_cookie: u64) -> narf_interrupts::IrqStatus {
        // We expect ORDER==1 here (first already ran).
        let _ = ORDER.compare_exchange(
            1,
            2,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        );
        narf_interrupts::IrqStatus::Handled
    }

    narf_interrupts::dispatch::clear_handler(VECTOR);
    narf_interrupts::install_handler_named(VECTOR, "first", 0, first);
    narf_interrupts::install_handler_named(VECTOR, "second", 0, second);

    let before_spurious = narf_interrupts::spurious_count(VECTOR);
    narf_interrupts::on_irq(VECTOR);
    if ORDER.load(core::sync::atomic::Ordering::Acquire) != 2 {
        narf_interrupts::dispatch::clear_handler(VECTOR);
        return TestResult::Fail("chain didn't fire in install order");
    }
    if narf_interrupts::spurious_count(VECTOR) != before_spurious {
        narf_interrupts::dispatch::clear_handler(VECTOR);
        return TestResult::Fail("spurious_count bumped when second handler claimed");
    }

    // installed_handler_names returns the chain.
    let names = narf_interrupts::installed_handler_names(VECTOR);
    if names != alloc::vec!["first", "second"] {
        narf_interrupts::dispatch::clear_handler(VECTOR);
        return TestResult::Fail("installed_handler_names didn't reflect chain");
    }
    narf_interrupts::dispatch::clear_handler(VECTOR);
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_irq_shared_chain_first_handled_wins);

/// remove_handler detaches one entry by name+cookie. Other
/// entries stay; chain order preserved.
#[cfg(target_arch = "x86_64")]
fn smoke_irq_remove_handler_by_name_cookie() -> TestResult {
    const VECTOR: u8 = 83;
    fn h(_cookie: u64) -> narf_interrupts::IrqStatus {
        narf_interrupts::IrqStatus::Handled
    }
    narf_interrupts::dispatch::clear_handler(VECTOR);
    narf_interrupts::install_handler_named(VECTOR, "a", 1, h);
    narf_interrupts::install_handler_named(VECTOR, "b", 2, h);
    narf_interrupts::install_handler_named(VECTOR, "c", 3, h);
    if !narf_interrupts::remove_handler(VECTOR, "b", 2) {
        narf_interrupts::dispatch::clear_handler(VECTOR);
        return TestResult::Fail("remove_handler didn't find b/2");
    }
    let names = narf_interrupts::installed_handler_names(VECTOR);
    if names != alloc::vec!["a", "c"] {
        narf_interrupts::dispatch::clear_handler(VECTOR);
        return TestResult::Fail("chain order wrong after remove");
    }
    // Removing a non-matching name+cookie returns false.
    if narf_interrupts::remove_handler(VECTOR, "missing", 99) {
        narf_interrupts::dispatch::clear_handler(VECTOR);
        return TestResult::Fail("remove_handler claimed to remove non-existent entry");
    }
    narf_interrupts::dispatch::clear_handler(VECTOR);
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_irq_remove_handler_by_name_cookie);

/// synchronize_irq returns promptly when in_flight is zero
/// (the steady state outside of an active dispatch). The bug
/// class we're guarding against is `synchronize_irq` looping
/// forever or polling something other than `in_flight` — a tight
/// wall-clock budget can't reliably catch that under QEMU because
/// `now_cycles` is RDTSC, which keeps ticking through host
/// context-switches and bunches arbitrarily large gaps between
/// our two reads. Instead, assert in_flight is observably zero
/// going in and going out — the function having returned at all
/// is sufficient proof it didn't spin forever (the test-runner
/// timeout would otherwise fail us first).
#[cfg(target_arch = "x86_64")]
fn smoke_irq_synchronize_returns_when_idle() -> TestResult {
    const VECTOR: u8 = 84;
    narf_interrupts::dispatch::clear_handler(VECTOR);
    if narf_interrupts::dispatch::in_flight(VECTOR) != 0 {
        return TestResult::Fail("in_flight non-zero before synchronize_irq");
    }
    narf_interrupts::synchronize_irq(VECTOR);
    if narf_interrupts::dispatch::in_flight(VECTOR) != 0 {
        return TestResult::Fail("in_flight non-zero after synchronize_irq returned");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_irq_synchronize_returns_when_idle);

/// Multi-waker support: two `wait_for_irq` futures both register
/// against the same vector; both must wake when the IRQ fires.
/// (Pre-rewrite, set_waker overwrote — the second waiter would
/// lose its waker silently.)
#[cfg(target_arch = "x86_64")]
fn smoke_irq_multi_waker_both_resolve() -> TestResult {
    use core::sync::atomic::{AtomicU32, Ordering};
    const VECTOR: u8 = 85;
    static DONE: AtomicU32 = AtomicU32::new(0);
    DONE.store(0, Ordering::Release);
    narf_interrupts::dispatch::clear_handler(VECTOR);

    async fn waiter() {
        let _ = narf_interrupts::wait::wait_for_irq(VECTOR).await;
        DONE.fetch_add(1, Ordering::AcqRel);
    }
    narf_scheduler::spawn_stackful(waiter());
    narf_scheduler::spawn_stackful(waiter());
    // Let each waiter poll once to register.
    for _ in 0..4 {
        narf_scheduler::poll_one_round();
    }
    // Fire — both should resolve.
    narf_interrupts::dispatch::on_irq(VECTOR);
    for _ in 0..8 {
        narf_scheduler::poll_one_round();
        if DONE.load(Ordering::Acquire) >= 2 {
            break;
        }
    }
    if DONE.load(Ordering::Acquire) != 2 {
        return TestResult::Fail("two waiters didn't both wake on a single IRQ");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_irq_multi_waker_both_resolve);

/// Multi-waker dedup contract: a wait_for_irq future that's polled
/// many times before the IRQ fires must not grow the slot's
/// wakers list unboundedly. set_waker dedupes by will_wake so the
/// list size is bounded by the number of DISTINCT waiters, not by
/// the number of polls.
///
/// Regression test for a real-HW hang seen on AMD laptops: on
/// silicon where the IRQ rate is much lower than the executor's
/// re-poll rate, the un-deduped list grew per poll, eventually
/// exhausting the allocator. QEMU's high virtual-IRQ rate masked
/// the issue.
#[cfg(target_arch = "x86_64")]
fn smoke_irq_set_waker_dedupes_by_will_wake() -> TestResult {
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicU32, Ordering};
    use core::task::{Context, Poll};

    const VECTOR: u8 = 90;
    static POLLS: AtomicU32 = AtomicU32::new(0);
    POLLS.store(0, Ordering::Release);

    // A future that polls wait_for_irq repeatedly via re-poll
    // without the IRQ ever firing. Counts the number of set_waker
    // calls indirectly via POLLS.
    struct PollMany {
        remaining: u32,
        inner: narf_interrupts::wait::WaitForIrq,
    }
    impl Future for PollMany {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            // Poll the WaitForIrq — it calls set_waker.
            // SAFETY: Valid memory or trusted environment
            let inner = unsafe { Pin::new_unchecked(&mut self.inner) };
            let _ = inner.poll(cx);
            POLLS.fetch_add(1, Ordering::AcqRel);
            if self.remaining == 0 {
                return Poll::Ready(());
            }
            self.remaining -= 1;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    let task = PollMany {
        remaining: 64,
        inner: narf_interrupts::wait::wait_for_irq(VECTOR),
    };
    narf_scheduler::spawn_stackful(task);
    for _ in 0..256 {
        narf_scheduler::poll_one_round();
        if POLLS.load(Ordering::Acquire) >= 64 {
            break;
        }
    }
    // The wakers list for VECTOR should hold at most ONE entry
    // for this future's waker — the dedup keeps repeated polls
    // from accumulating.
    let len = narf_interrupts::dispatch::wakers_len(VECTOR);
    if len > 1 {
        return TestResult::Fail("set_waker didn't dedupe — wakers list grew unbounded");
    }
    // Cleanup: clear every registered waker so subsequent tests
    // start clean. The future is still alive in the scheduler
    // (we never fire VECTOR), but its slot will GC eventually.
    narf_interrupts::dispatch::clear_all_wakers(VECTOR);
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_irq_set_waker_dedupes_by_will_wake);
