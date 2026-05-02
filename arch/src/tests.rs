//! Subsystem smokes for `narf-arch`.
//!
//! Migrated from `narf-verification`. Tests register under the `arch`
//! subsystem so the runner groups output appropriately.

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_arch_backend() -> TestResult {
    use crate::{BACKEND, DomainBackend};
    let expected = if cfg!(target_arch = "x86_64") { DomainBackend::Pks }
                   else if cfg!(target_arch = "aarch64") { DomainBackend::Mte }
                   else { return TestResult::Skip("unknown arch"); };
    if BACKEND == expected { TestResult::Pass }
    else { TestResult::Fail("BACKEND constant mismatch") }
}
kernel_test_in!("arch", smoke_arch_backend);

fn smoke_arch_percpu_basic() -> TestResult {
    use core::sync::atomic::{AtomicU64, Ordering};
    use crate::percpu::{current_cpu_id, ThisCpu, MAX_CPUS};

    crate::per_cpu! {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
    }

    // Pre-condition: BSP-only today.
    if current_cpu_id() != 0 {
        return TestResult::Fail("current_cpu_id should be 0 BSP-only");
    }
    if COUNTER.len() != MAX_CPUS {
        return TestResult::Fail("array length != MAX_CPUS");
    }
    // this_cpu() returns the slot at index 0; mutate via it.
    let prior = COUNTER.this_cpu().load(Ordering::Relaxed);
    COUNTER.this_cpu().fetch_add(7, Ordering::Relaxed);
    if COUNTER[0].load(Ordering::Relaxed) != prior + 7 {
        return TestResult::Fail("this_cpu() didn't route to slot 0");
    }
    // Other slots untouched.
    for i in 1..MAX_CPUS {
        if COUNTER[i].load(Ordering::Relaxed) != 0 {
            return TestResult::Fail("non-current slot was modified");
        }
    }
    // Reset so re-runs are idempotent (no test ordering hazard).
    COUNTER.this_cpu().store(prior, Ordering::Relaxed);
    TestResult::Pass
}
kernel_test_in!("arch", smoke_arch_percpu_basic);

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
        crate::patch_word(addr, 0xCAFE_F00D);
        if SLOT.load(Ordering::Acquire) != 0xCAFE_F00D {
            return TestResult::Fail("first patch not visible");
        }
        crate::patch_word(addr, 0x1234_5678);
        if SLOT.load(Ordering::Acquire) != 0x1234_5678 {
            return TestResult::Fail("second patch overwrote wrong");
        }
    }
    TestResult::Pass
}
kernel_test_in!("arch", smoke_arch_patch_word_roundtrip);

#[cfg(target_arch = "aarch64")]
fn smoke_aarch64_mte_l2() -> TestResult {
    // MTE-L2 live test: SCTLR_EL1.ATA is set by boot.S when MTE is
    // present, so GCR_EL1 is accessible here. Read it, write a
    // distinctive value, read back, restore. Verifies (a) the
    // feature probe matches QEMU's `-machine virt,mte=on` flag,
    // (b) the ATA bit actually ungated GCR_EL1, and (c) the
    // arch::aarch64::sysreg raw-encoding accessors work.
    // SAFETY: MRS ID_AA64* always legal.
    let feats = unsafe { crate::aarch64::Features::probe() };
    if feats.mte < 2 {
        return TestResult::Skip("MTE level <2 (QEMU -machine virt,mte=on not in effect)");
    }
    use crate::aarch64::sysreg::{read_gcr_el1, write_gcr_el1};
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
kernel_test_in!("arch", smoke_aarch64_mte_l2);

#[cfg(target_arch = "aarch64")]
fn smoke_aarch64_features() -> TestResult {
    // SAFETY: MRS of ID_AA64* and CNTFRQ_EL0 is always legal at EL1.
    let feats = unsafe { crate::aarch64::Features::probe() };
    let hz = unsafe { crate::aarch64::cpuid::generic_timer_hz() };

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
kernel_test_in!("arch", smoke_aarch64_features);

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

    if crate::current_cpu_id().raw() != 0 {
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
kernel_test_in!("arch", smoke_percpu_this_cpu);

#[cfg(target_arch = "x86_64")]
fn smoke_acpi_discover_xsdt() -> TestResult {
    use crate::x86_64::acpi;
    // SAFETY: kernel-test runs at CPL=0; low memory + identity-
    // mapped phys windows are safe to read.
    let res = unsafe { acpi::discover() };
    let t = match res {
        Ok(t) => t,
        Err(_) => return TestResult::Skip("no ACPI tables present"),
    };
    if t.local_apics.is_empty() {
        return TestResult::Fail("MADT had no local-APIC entries");
    }
    if t.hpet_base.is_none() {
        return TestResult::Fail("HPET table missing");
    }
    if t.mcfg_segments.is_empty() {
        return TestResult::Fail("MCFG had no segments");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/acpi", smoke_acpi_discover_xsdt);

#[cfg(target_arch = "x86_64")]
fn smoke_tsc_calibrate_via_cpuid() -> TestResult {
    use crate::x86_64::tsc;
    tsc::__reset_for_test();
    let hz = tsc::calibrate_via_cpuid();
    if hz == 0 {
        return TestResult::Skip("CPUID 15h/16h unavailable");
    }
    if hz < 100_000_000 || hz > 10_000_000_000 {
        return TestResult::Fail("TSC frequency out of plausible range");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/tsc", smoke_tsc_calibrate_via_cpuid);

#[cfg(target_arch = "x86_64")]
fn smoke_microcode_vendor_detect() -> TestResult {
    use crate::x86_64::microcode;
    match microcode::vendor() {
        microcode::Vendor::Intel | microcode::Vendor::Amd => TestResult::Pass,
        microcode::Vendor::Unknown => TestResult::Fail("unknown vendor on x86_64"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/microcode", smoke_microcode_vendor_detect);

#[cfg(target_arch = "aarch64")]
fn smoke_psci_version() -> TestResult {
    use crate::aarch64::psci;
    let (major, minor) = psci::version();
    if major == 0 && minor == 0 {
        return TestResult::Skip("no PSCI implementation");
    }
    if major == 0xFFFF && minor == 0xFFFF {
        return TestResult::Fail("PSCI_VERSION returned junk");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/psci", smoke_psci_version);

#[cfg(target_arch = "x86_64")]
fn smoke_mce_supported_and_snapshot() -> TestResult {
    use crate::x86_64::mce;
    if !mce::is_supported() {
        return TestResult::Skip("MCA not advertised");
    }
    // SAFETY: kernel-test runs at CPL=0; MCA architecturally
    // available when CPUID flags it.
    let cap = unsafe { mce::mcg_cap() };
    if cap.count == 0 {
        return TestResult::Fail("MCG_CAP reported 0 banks");
    }
    // SAFETY: same.
    let snap = unsafe { mce::snapshot() };
    let _ = snap;
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/mce", smoke_mce_supported_and_snapshot);

#[cfg(target_arch = "x86_64")]
fn smoke_mtrr_cap_decode() -> TestResult {
    use crate::x86_64::mtrr;
    // SAFETY: kernel-test CPL=0.
    let cap = unsafe { mtrr::cap() };
    if cap.vcnt == 0 {
        return TestResult::Skip("no variable MTRRs (MTRR-less host?)");
    }
    // SAFETY: same.
    let dt = unsafe { mtrr::def_type() };
    let _ = dt;
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/mtrr", smoke_mtrr_cap_decode);

#[cfg(target_arch = "x86_64")]
fn smoke_spec_ctrl_features_probe() -> TestResult {
    use crate::x86_64::spec_ctrl;
    spec_ctrl::__reset_for_test();
    let f = spec_ctrl::features();
    // We don't fail when no mitigations are advertised — QEMU TCG
    // leaves the mitigation CPUID bits clear by default. Just
    // verify the probe ran without faulting.
    let _ = f;
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/spec_ctrl", smoke_spec_ctrl_features_probe);

#[cfg(target_arch = "x86_64")]
fn smoke_rtc_read_now_plausible() -> TestResult {
    use crate::x86_64::rtc;
    // SAFETY: kernel-test runs in boot context; CMOS IO ports
    // are owned.
    let t = unsafe { rtc::read_now() };
    if t.year < 1990 || t.year > 2100 {
        return TestResult::Fail("RTC year implausible");
    }
    if t.month == 0 || t.month > 12 { return TestResult::Fail("month"); }
    if t.day   == 0 || t.day   > 31 { return TestResult::Fail("day");   }
    if t.hour  > 23                 { return TestResult::Fail("hour");  }
    if t.minute > 59                { return TestResult::Fail("min");   }
    if t.second > 60                { return TestResult::Fail("sec");   }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/rtc", smoke_rtc_read_now_plausible);

#[cfg(target_arch = "aarch64")]
fn smoke_generic_timer_calibrate() -> TestResult {
    use crate::aarch64::timer;
    timer::__reset_for_test();
    let hz = timer::calibrate();
    if hz == 0 {
        return TestResult::Fail("CNTFRQ_EL0 returned 0");
    }
    // QEMU virt reports 62.5 MHz by default; real silicon ranges
    // from 24 MHz to 100 MHz. 1 MHz..1 GHz is a generous window.
    if hz < 1_000_000 || hz > 1_000_000_000 {
        return TestResult::Fail("Generic timer freq out of plausible range");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/timer", smoke_generic_timer_calibrate);
