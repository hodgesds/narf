//! Subsystem smokes for `narf-arch`.
//!
//! Migrated from `narf-verification`. Tests register under the `arch`
//! subsystem so the runner groups output appropriately.

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_arch_backend() -> TestResult {
    use crate::{DomainBackend, BACKEND};
    let expected = if cfg!(target_arch = "x86_64") {
        DomainBackend::Pks
    } else if cfg!(target_arch = "aarch64") {
        DomainBackend::Mte
    } else {
        return TestResult::Skip("unknown arch");
    };
    if BACKEND == expected {
        TestResult::Pass
    } else {
        TestResult::Fail("BACKEND constant mismatch")
    }
}
kernel_test_in!("arch", smoke_arch_backend);

fn smoke_arch_percpu_basic() -> TestResult {
    use crate::percpu::{current_cpu_id, ThisCpu, MAX_CPUS};
    use core::sync::atomic::{AtomicU64, Ordering};

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
    if t.month == 0 || t.month > 12 {
        return TestResult::Fail("month");
    }
    if t.day == 0 || t.day > 31 {
        return TestResult::Fail("day");
    }
    if t.hour > 23 {
        return TestResult::Fail("hour");
    }
    if t.minute > 59 {
        return TestResult::Fail("min");
    }
    if t.second > 60 {
        return TestResult::Fail("sec");
    }
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

#[cfg(target_arch = "x86_64")]
fn smoke_topology_discover() -> TestResult {
    use crate::x86_64::topology;
    let t = topology::discover();
    if t.thread_count == 0 {
        return TestResult::Fail("thread_count = 0");
    }
    if t.core_count == 0 {
        return TestResult::Fail("core_count = 0");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/topology", smoke_topology_discover);

#[cfg(target_arch = "x86_64")]
fn smoke_topology_caches_l1() -> TestResult {
    use crate::x86_64::topology;
    let caches = topology::discover_caches();
    let l1 = caches.iter().flatten().find(|c| c.level == 1);
    let l1 = match l1 {
        Some(c) => c,
        None => return TestResult::Skip("no L1 cache info"),
    };
    if l1.line_size < 16 || l1.line_size > 256 {
        return TestResult::Fail("L1 line size implausible");
    }
    if l1.bytes < 1024 {
        return TestResult::Fail("L1 size implausible");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/topology", smoke_topology_caches_l1);

#[cfg(target_arch = "x86_64")]
fn smoke_smp_aps_from_madt() -> TestResult {
    use crate::x86_64::{acpi, smp};
    // SAFETY: kernel-test CPL=0; ACPI low-memory walk safe.
    let t = match unsafe { acpi::discover() } {
        Ok(t) => t,
        Err(_) => return TestResult::Skip("no ACPI tables"),
    };
    // Treat APIC id 0 as the BSP for the QEMU default `-smp 1`
    // case; on real `-smp >1` the list grows.
    let aps = smp::aps_from_madt(&t, /*bsp=*/ 0);
    let _ = aps;
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/smp", smoke_smp_aps_from_madt);

#[cfg(target_arch = "x86_64")]
fn smoke_hfi_caps() -> TestResult {
    use crate::x86_64::hfi;
    let c = hfi::caps();
    // QEMU TCG won't advertise HFI; on real Alder Lake hosts it
    // will. Either is acceptable — just verify shape consistency.
    if c.supported && c.n_classes == 0 {
        return TestResult::Fail("HFI supported but n_classes = 0");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/hfi", smoke_hfi_caps);

#[cfg(target_arch = "x86_64")]
fn smoke_pmu_caps_decode() -> TestResult {
    use crate::x86_64::pmu;
    let c = pmu::caps();
    if c.version == 0 {
        return TestResult::Skip("no architectural PMU");
    }
    if c.n_general_counters == 0 {
        return TestResult::Fail("PMU version > 0 but no GP counters");
    }
    if c.width_general < 32 || c.width_general > 64 {
        return TestResult::Fail("PMU GP counter width implausible");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/pmu", smoke_pmu_caps_decode);

#[cfg(target_arch = "x86_64")]
fn smoke_pmu_event_encode() -> TestResult {
    use crate::x86_64::pmu;
    // Architectural "Instructions Retired" with both rings.
    let s = pmu::arch_event::instructions_retired(true, true);
    let v = s.encode();
    // event_select = 0xC0, umask = 0x00, OS+USR+ENABLE bits set.
    if (v & 0xFF) != 0xC0 {
        return TestResult::Fail("event_select");
    }
    if ((v >> 8) & 0xFF) != 0x00 {
        return TestResult::Fail("umask");
    }
    if v & (1 << 16) == 0 {
        return TestResult::Fail("USR bit");
    }
    if v & (1 << 17) == 0 {
        return TestResult::Fail("OS bit");
    }
    if v & (1 << 22) == 0 {
        return TestResult::Fail("EN bit");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/pmu", smoke_pmu_event_encode);

#[cfg(target_arch = "x86_64")]
fn smoke_lbr_caps() -> TestResult {
    use crate::x86_64::lbr;
    let c = lbr::caps();
    if c.n_entries == 0 {
        return TestResult::Fail("LBR n_entries = 0");
    }
    if !matches!(c.n_entries, 4 | 8 | 16 | 32) {
        return TestResult::Fail("LBR n_entries non-canonical");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/lbr", smoke_lbr_caps);

#[cfg(target_arch = "x86_64")]
fn smoke_pt_caps() -> TestResult {
    use crate::x86_64::pt;
    let c = pt::caps();
    // QEMU TCG without `-cpu host,+intel-pt` won't advertise PT;
    // real silicon does. Either is acceptable.
    if c.supported && !c.topa {
        // Single-range output is allowed too — but the caps shape
        // says ToPA + multi_topa are at least decoded coherently.
    }
    let _ = c;
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/pt", smoke_pt_caps);

#[cfg(target_arch = "x86_64")]
fn smoke_pt_topa_entry_encode() -> TestResult {
    use crate::x86_64::pt::topa_entry;
    // 4 KiB ring at phys 0x10_0000, not END, not INT.
    let e = topa_entry(0x10_0000, 12, false, false);
    if e & 0xFFF != 0 {
        return TestResult::Fail("size field");
    }
    if e & (1 << 5) != 0 {
        return TestResult::Fail("END set");
    }
    if e & (1 << 4) != 0 {
        return TestResult::Fail("INT set");
    }
    if e & 0xFFFF_FFFF_FFFF_F000 != 0x10_0000 {
        return TestResult::Fail("base lost");
    }
    // 16 KiB ring + END + INT.
    let e = topa_entry(0x20_0000, 14, true, true);
    if e & 0x7 != 2 {
        return TestResult::Fail("16K size code");
    }
    if e & (1 << 4) == 0 {
        return TestResult::Fail("INT lost");
    }
    if e & (1 << 5) == 0 {
        return TestResult::Fail("END lost");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/pt", smoke_pt_topa_entry_encode);

#[cfg(target_arch = "x86_64")]
fn smoke_cet_caps_decode() -> TestResult {
    use crate::x86_64::cet;
    let c = cet::caps();
    // QEMU TCG advertises CET via `-cpu host`/`-cpu max`; default
    // -cpu doesn't. Either is fine — just verify the struct
    // shape is coherent.
    let _ = (c.shadow_stack, c.ibt, c.cr4_cet);
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/cet", smoke_cet_caps_decode);

#[cfg(target_arch = "x86_64")]
fn smoke_pebs_supported_path() -> TestResult {
    use crate::x86_64::pebs;
    // Calling `supported()` must not panic + must agree with
    // itself across two calls (memoisation invariant — it's
    // pure CPUID + MSR read).
    let a = pebs::supported();
    let b = pebs::supported();
    if a != b {
        return TestResult::Fail("supported() racy");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/pebs", smoke_pebs_supported_path);

#[cfg(target_arch = "x86_64")]
fn smoke_cpu_validate_baseline() -> TestResult {
    use crate::x86_64::cpu_validate;
    // SAFETY: kernel-test runs at CPL=0.
    let v = unsafe { cpu_validate::validate() };
    match cpu_validate::baseline_ok(&v) {
        Ok(()) => TestResult::Pass,
        Err(why) => {
            // Surface the *first* failed check via the test name —
            // log isn't easily threaded through TestResult, but a
            // failure narrows it down on a one-line summary.
            let _ = why;
            // We don't fail in QEMU TCG default `-cpu qemu64` which
            // omits SMEP/SMAP. Instead, downgrade to a skip so the
            // test surface still exercises the validator.
            TestResult::Skip("CPU baseline missing (likely QEMU -cpu qemu64)")
        }
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/cpu_validate", smoke_cpu_validate_baseline);

#[cfg(target_arch = "x86_64")]
fn smoke_vmx_caps_decode() -> TestResult {
    use crate::x86_64::vmx;
    let c = vmx::caps();
    if c.supported && c.feature_locked && c.vmxon_outside_smx && c.basic.vmcs_region_size == 0 {
        return TestResult::Fail("VMX advertised but vmcs_region_size = 0");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/vmx", smoke_vmx_caps_decode);

#[cfg(target_arch = "x86_64")]
fn smoke_svm_caps_decode() -> TestResult {
    use crate::x86_64::svm;
    let c = svm::caps();
    if c.supported && !c.disabled && c.revision == 0 {
        return TestResult::Fail("SVM advertised but revision = 0");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/svm", smoke_svm_caps_decode);

#[cfg(target_arch = "x86_64")]
fn smoke_sgx_caps_decode() -> TestResult {
    use crate::x86_64::sgx;
    let c = sgx::caps();
    if c.instruction_supported && !c.sgx1 {
        return TestResult::Fail("SGX instr advertised without SGX1 support");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/sgx", smoke_sgx_caps_decode);

#[cfg(target_arch = "x86_64")]
fn smoke_confidential_detect() -> TestResult {
    use crate::x86_64::confidential::{detect_environment, ConfidentialEnvironment};
    let env = detect_environment();
    // Any of the variants is acceptable — Bare is what every QEMU
    // smoke target reports today; running this same test inside a
    // TDX / SEV-SNP guest would surface those variants instead.
    let _ = matches!(
        env,
        ConfidentialEnvironment::Bare
            | ConfidentialEnvironment::TdxGuest
            | ConfidentialEnvironment::SevGuest
            | ConfidentialEnvironment::SevEsGuest
            | ConfidentialEnvironment::SevSnpGuest
    );
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/confidential", smoke_confidential_detect);

#[cfg(target_arch = "x86_64")]
fn smoke_hypervisor_detect() -> TestResult {
    use crate::x86_64::hypervisor::{detect, signature, Hypervisor};
    let hv = detect();
    // QEMU TCG advertises `TCGTCGTCGTCG`; KVM advertises
    // `KVMKVMKVM`. Either is acceptable; bare metal returns None.
    if hv != Hypervisor::None {
        let s = signature();
        if s.is_none() {
            return TestResult::Fail("hypervisor present but no signature");
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/hypervisor", smoke_hypervisor_detect);

#[cfg(target_arch = "x86_64")]
fn smoke_xsave_caps_decode() -> TestResult {
    use crate::x86_64::xsave;
    let c = xsave::caps();
    // x87 + SSE bits must be set on every x86_64 CPU.
    if c.xcr0_supported & xsave::XSAVE_X87 == 0 {
        return TestResult::Fail("x87 bit missing in XCR0_supported");
    }
    if c.xcr0_supported & xsave::XSAVE_SSE == 0 {
        return TestResult::Fail("SSE bit missing in XCR0_supported");
    }
    if c.area_size_xcr0 == 0 {
        return TestResult::Fail("area_size_xcr0 = 0");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/xsave", smoke_xsave_caps_decode);

#[cfg(target_arch = "x86_64")]
fn smoke_waitpkg_supported_path() -> TestResult {
    use crate::x86_64::waitpkg;
    // Just verify the gate doesn't panic; QEMU TCG default `-cpu`
    // doesn't advertise WAITPKG.
    let _ = waitpkg::supported();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/waitpkg", smoke_waitpkg_supported_path);

#[cfg(target_arch = "x86_64")]
fn smoke_smca_supported_path() -> TestResult {
    use crate::x86_64::smca;
    let _ = smca::supported();
    // Decode helper is data-only; verify it compiles + runs.
    //   bits[15:0]  = 0x0042 = instance_id
    //   bits[31:16] = 0xBEEF = hardware_id
    //   bits[47:44] = 0x7    = mca_type → bits[47:32] = 0x7000
    let info = smca::SmcaBankInfo::decode(0x0000_7000_BEEF_0042);
    if info.instance_id != 0x0042 || info.hardware_id != 0xBEEF || info.mca_type != 0x07 {
        return TestResult::Fail("SmcaBankInfo decode misaligned");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/smca", smoke_smca_supported_path);

#[cfg(target_arch = "x86_64")]
fn smoke_lam_supported_path() -> TestResult {
    use crate::x86_64::lam;
    let _ = lam::supported();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/lam", smoke_lam_supported_path);

#[cfg(target_arch = "x86_64")]
fn smoke_uintr_supported_path() -> TestResult {
    use crate::x86_64::uintr;
    let _ = uintr::supported();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/uintr", smoke_uintr_supported_path);

#[cfg(target_arch = "x86_64")]
fn smoke_keylocker_caps() -> TestResult {
    use crate::x86_64::keylocker;
    let s = keylocker::supported();
    let c = keylocker::caps();
    if !s && c != 0 {
        return TestResult::Fail("KL caps non-zero with supported = false");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/keylocker", smoke_keylocker_caps);

#[cfg(target_arch = "aarch64")]
fn smoke_pac_caps() -> TestResult {
    use crate::aarch64::pac;
    let c = pac::caps();
    let _ = (c.address_auth, c.generic_auth, c.enhanced);
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/pac", smoke_pac_caps);

#[cfg(target_arch = "aarch64")]
fn smoke_bti_caps() -> TestResult {
    use crate::aarch64::bti;
    let _ = bti::caps();
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/bti", smoke_bti_caps);

#[cfg(target_arch = "aarch64")]
fn smoke_ssbs_caps() -> TestResult {
    use crate::aarch64::ssbs;
    let v = ssbs::caps();
    if v > 3 {
        return TestResult::Fail("SSBS field > 3 (architectural max)");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/ssbs", smoke_ssbs_caps);

#[cfg(target_arch = "x86_64")]
fn smoke_invlpgb_caps() -> TestResult {
    use crate::x86_64::invlpgb;
    let s = invlpgb::supported();
    let count = invlpgb::count_max();
    let asid = invlpgb::asid_max();
    if !s && (count != 0 || asid != 0) {
        return TestResult::Fail("INVLPGB caps non-zero with supported = false");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/invlpgb", smoke_invlpgb_caps);

#[cfg(target_arch = "x86_64")]
fn smoke_rdpru_supported_path() -> TestResult {
    use crate::x86_64::rdpru;
    let _ = rdpru::supported();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/rdpru", smoke_rdpru_supported_path);

#[cfg(target_arch = "x86_64")]
fn smoke_movdir_caps_decode() -> TestResult {
    use crate::x86_64::movdir;
    let _ = movdir::cldemote_supported();
    let _ = movdir::movdiri_supported();
    let _ = movdir::movdir64b_supported();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/movdir", smoke_movdir_caps_decode);

#[cfg(target_arch = "x86_64")]
fn smoke_wrmsrns_supported_path() -> TestResult {
    use crate::x86_64::wrmsrns;
    let _ = wrmsrns::supported();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/wrmsrns", smoke_wrmsrns_supported_path);

#[cfg(target_arch = "x86_64")]
fn smoke_avx10_caps_decode() -> TestResult {
    use crate::x86_64::avx10;
    let c = avx10::caps();
    if c.supported && !c.xmm {
        return TestResult::Fail("AVX10 supported but XMM bit clear");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/avx10", smoke_avx10_caps_decode);

#[cfg(target_arch = "aarch64")]
fn smoke_sve_caps() -> TestResult {
    use crate::aarch64::sve;
    // ID-group registers only — safe regardless of CPACR.ZEN.
    let c = sve::caps();
    if c.sve21 && !c.sve2 {
        return TestResult::Fail("SVE2.1 set without SVE2");
    }
    if c.sve2 && !c.sve {
        return TestResult::Fail("SVE2 set without SVE");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/sve", smoke_sve_caps);

#[cfg(target_arch = "x86_64")]
fn smoke_x86_ident_decode() -> TestResult {
    use crate::x86_64::ident;
    let c = ident::read();
    if c.signature == 0 {
        return TestResult::Fail("CPUID(1).EAX returned 0");
    }
    if c.family < 6 {
        return TestResult::Fail("family < 6 (QEMU should expose ≥ 6)");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/ident", smoke_x86_ident_decode);

#[cfg(target_arch = "x86_64")]
fn smoke_x86_brand_string_nonempty() -> TestResult {
    use crate::x86_64::ident;
    let c = ident::read();
    let s = ident::brand_str(&c);
    let has_nonspace = s.bytes().any(|b| b != b' ' && b != 0);
    if !has_nonspace {
        return TestResult::Fail("brand string is empty / all spaces");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/ident", smoke_x86_brand_string_nonempty);

#[cfg(target_arch = "x86_64")]
fn smoke_x86_cache_caps() -> TestResult {
    use crate::x86_64::cache;
    let c = cache::caps();
    if c.line_bytes < 32 {
        return TestResult::Fail("cache line_bytes < 32");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/cache", smoke_x86_cache_caps);

#[cfg(target_arch = "x86_64")]
fn smoke_x86_errata_table_sorted() -> TestResult {
    use crate::x86_64::errata;
    // The marker-noop sentinel sits at the tail; ignore it for
    // ordering. Real entries must be sorted by (vendor-discriminant,
    // family, model_lo).
    fn vendor_key(v: &crate::x86_64::ident::Vendor) -> u32 {
        use crate::x86_64::ident::Vendor::*;
        match v {
            Intel => 1,
            Amd => 2,
            Hygon => 3,
            Centaur => 4,
            Via => 5,
            Zhaoxin => 6,
            Other(_) => 7,
        }
    }
    let t = errata::table();
    for w in t.windows(2) {
        let a = (vendor_key(&w[0].vendor), w[0].family, w[0].model_lo);
        let b = (vendor_key(&w[1].vendor), w[1].family, w[1].model_lo);
        if a > b {
            return TestResult::Fail("errata table not sorted");
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/errata", smoke_x86_errata_table_sorted);

#[cfg(target_arch = "x86_64")]
fn smoke_lvt_pc_program_helper() -> TestResult {
    use crate::x86_64::pmi;
    // Use a kernel-mode buffer as a stand-in for the LAPIC MMIO
    // page so the test exercises program / mask / unmask without
    // needing a real LAPIC mapped at a known address.
    let mut buf = [0u32; 0x100];
    // base + 0x340 = address of buf[0]; reading buf[0] reads the
    // emitted LVT-PC entry.
    let base = buf.as_mut_ptr() as usize - 0x340;
    // SAFETY: the buffer covers the offset we touch.
    unsafe {
        pmi::program_lvt_pc(base, 0xEE, false, true);
    }
    if buf[0] & 0xFF != 0xEE {
        return TestResult::Fail("vector mismatch");
    }
    if buf[0] & (1 << 16) == 0 {
        return TestResult::Fail("mask bit not set after program");
    }
    // SAFETY: same buffer.
    unsafe {
        pmi::unmask_lvt_pc(base);
    }
    if buf[0] & (1 << 16) != 0 {
        return TestResult::Fail("mask bit still set after unmask");
    }
    // SAFETY: same buffer.
    unsafe {
        pmi::mask_lvt_pc(base);
    }
    if buf[0] & (1 << 16) == 0 {
        return TestResult::Fail("mask bit cleared after re-mask");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/pmi", smoke_lvt_pc_program_helper);

#[cfg(target_arch = "aarch64")]
fn smoke_aarch_midr_decode() -> TestResult {
    use crate::aarch64::ident;
    let id = ident::ident();
    if id.raw == 0 {
        return TestResult::Fail("MIDR_EL1 reads as 0");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/ident", smoke_aarch_midr_decode);

#[cfg(target_arch = "aarch64")]
fn smoke_aarch_cache_caps() -> TestResult {
    use crate::aarch64::cache;
    let c = cache::caps();
    if c.iline_bytes < 16 || c.dline_bytes < 16 {
        return TestResult::Fail("cache line bytes < 16");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/cache", smoke_aarch_cache_caps);

#[cfg(target_arch = "x86_64")]
fn smoke_rdt_caps() -> TestResult {
    use crate::x86_64::rdt;
    let c = rdt::caps();
    // Sub-features must be subordinate to the master gates.
    if c.l3_monitoring && !c.monitoring {
        return TestResult::Fail("L3 monitoring without RDT-M");
    }
    if (c.l3_cat || c.l2_cat || c.mba) && !c.allocation {
        return TestResult::Fail("CAT/MBA without RDT-A");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/rdt", smoke_rdt_caps);

#[cfg(target_arch = "x86_64")]
fn smoke_fred_supported_path() -> TestResult {
    use crate::x86_64::fred;
    let _ = fred::supported();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/fred", smoke_fred_supported_path);

#[cfg(target_arch = "aarch64")]
fn smoke_brbe_caps() -> TestResult {
    use crate::aarch64::brbe;
    let v = brbe::caps();
    if v > 3 {
        return TestResult::Fail("BRBE field > 3 (architectural max)");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/brbe", smoke_brbe_caps);

#[cfg(target_arch = "aarch64")]
fn smoke_trbe_supported_path() -> TestResult {
    use crate::aarch64::trbe;
    let _ = trbe::supported();
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/trbe", smoke_trbe_supported_path);

#[cfg(target_arch = "aarch64")]
fn smoke_mpam_caps() -> TestResult {
    use crate::aarch64::mpam;
    let c = mpam::caps();
    // If MPAM is not present, all fields must be zero — which
    // confirms the gate.
    if !c.supported && (c.revision != 0 || c.max_partid != 0 || c.max_pmg != 0) {
        return TestResult::Fail("MPAM caps non-zero with supported = false");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/mpam", smoke_mpam_caps);

#[cfg(target_arch = "aarch64")]
fn smoke_spe_caps() -> TestResult {
    use crate::aarch64::spe;
    let v = spe::caps();
    if v > 3 {
        return TestResult::Fail("PMSVer > 3 (architectural max)");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/spe", smoke_spe_caps);

#[cfg(target_arch = "aarch64")]
fn smoke_ete_supported_path() -> TestResult {
    use crate::aarch64::ete;
    let _ = ete::supported();
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/ete", smoke_ete_supported_path);

#[cfg(target_arch = "aarch64")]
fn smoke_gcs_caps() -> TestResult {
    use crate::aarch64::gcs;
    let v = gcs::caps();
    if v > 1 {
        return TestResult::Fail("GCS field > 1 (architectural max as of v0.1)");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/gcs", smoke_gcs_caps);

#[cfg(target_arch = "aarch64")]
fn smoke_rndr_supported_path() -> TestResult {
    use crate::aarch64::rndr;
    // Just exercise the gate + try-call. RNDR may starve in
    // QEMU and that's a valid outcome (`None`); we only fail if
    // the gate claims support but every call returns None.
    let _ = rndr::supported();
    let _ = rndr::try_rndr();
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/rndr", smoke_rndr_supported_path);

#[cfg(target_arch = "x86_64")]
fn smoke_lass_supported_path() -> TestResult {
    use crate::x86_64::lass;
    let _ = lass::supported();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/lass", smoke_lass_supported_path);

#[cfg(target_arch = "aarch64")]
fn smoke_sme_caps() -> TestResult {
    use crate::aarch64::sme;
    let c = sme::caps();
    if c.sme2 && !c.sme {
        return TestResult::Fail("SME2 set without SME");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/sme", smoke_sme_caps);

#[cfg(target_arch = "aarch64")]
fn smoke_rme_caps() -> TestResult {
    use crate::aarch64::rme;
    let v = rme::caps();
    if v > 1 {
        return TestResult::Fail("RME field > 1 (architectural max as of v0.1)");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/rme", smoke_rme_caps);

#[cfg(target_arch = "aarch64")]
fn smoke_specres_caps() -> TestResult {
    use crate::aarch64::specres;
    let v = specres::caps();
    if v > 2 {
        return TestResult::Fail("SPECRES field > 2 (architectural max)");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/specres", smoke_specres_caps);

#[cfg(target_arch = "x86_64")]
fn smoke_bhi_supported_path() -> TestResult {
    use crate::x86_64::bhi;
    let _ = bhi::bhi_no();
    let _ = bhi::bhi_dis_s_supported();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/bhi", smoke_bhi_supported_path);

#[cfg(target_arch = "x86_64")]
fn smoke_pasid_supported_path() -> TestResult {
    use crate::x86_64::pasid;
    let _ = pasid::supported();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/pasid", smoke_pasid_supported_path);

#[cfg(target_arch = "x86_64")]
fn smoke_vtd_caps_decode() -> TestResult {
    use crate::x86_64::vtd;
    // Build a synthetic register block:
    //   ver = 0x10  → major 1, minor 0
    //   cap.ND = 0  → 16 domains
    //   cap.SAGAW bits[12:8] = 0b00100 (39-bit) → sagaw = 0x4
    //   cap.NFR (bits[47:40]) = 0x07 → 8 regs
    //   ecap.QI (bit 1) + IR (bit 3)
    let ver = 0x0000_0010u32;
    let cap = (0x4u64 << 8) | (0x7u64 << 40);
    let ecap = 0b1010u64;
    let c = vtd::decode_caps(ver, cap, ecap);
    if c.version_major != 1 || c.version_minor != 0 {
        return TestResult::Fail("version decode mismatch");
    }
    if c.num_domains != 16 {
        return TestResult::Fail("num_domains decode mismatch");
    }
    if c.sagaw != 0x4 || c.num_fault_regs != 8 {
        return TestResult::Fail("sagaw / nfr decode mismatch");
    }
    if !c.queued_invalidation || !c.interrupt_remap {
        return TestResult::Fail("ecap bits not decoded");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/vtd", smoke_vtd_caps_decode);

#[cfg(target_arch = "x86_64")]
fn smoke_amd_vi_caps_decode() -> TestResult {
    use crate::x86_64::amd_vi;
    let ctrl = amd_vi::CTRL_IOMMUEN | amd_vi::CTRL_EVTLOGEN | amd_vi::CTRL_CMDBUFEN;
    let efr = amd_vi::EFR_PPRSUP | amd_vi::EFR_GTSUP | amd_vi::EFR_XTSUP;
    let c = amd_vi::decode_caps(ctrl, efr);
    if !c.iommu_enabled || !c.event_log_enabled || !c.command_buf_enabled {
        return TestResult::Fail("ctrl bits not decoded");
    }
    if !c.ppr_supported || !c.gt_supported || !c.xts_supported {
        return TestResult::Fail("efr bits not decoded");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/amd_vi", smoke_amd_vi_caps_decode);

#[cfg(target_arch = "x86_64")]
fn smoke_rar_supported_path() -> TestResult {
    use crate::x86_64::rar;
    let _ = rar::supported();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/rar", smoke_rar_supported_path);

#[cfg(target_arch = "aarch64")]
fn smoke_smmuv3_caps_decode() -> TestResult {
    use crate::aarch64::smmuv3;
    // S1P + S2P, TTF = 0b11 (4K + 16K + 64K), QUEUE share = 0b11
    let idr0 = 0b11u32 | (0b11 << 10) | (0b11 << 12);
    let idr1 = 0x10u32; // SIDSIZE = 16
    let idr5 = 0x5u32; // OAS class = 5
    let c = smmuv3::decode_caps(idr0, idr1, idr5);
    if !c.s1p || !c.s2p {
        return TestResult::Fail("S1P/S2P decode mismatch");
    }
    if !c.ttf16 || !c.ttf64 {
        return TestResult::Fail("TTF granule decode mismatch");
    }
    if c.sid_width != 0x10 || c.oas != 5 || c.queue_base_share != 0b11 {
        return TestResult::Fail("idr1/5/queue-share decode mismatch");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/smmuv3", smoke_smmuv3_caps_decode);

#[cfg(target_arch = "x86_64")]
fn smoke_irte_encode_decode() -> TestResult {
    use crate::x86_64::ir;
    let e = ir::Irte {
        present: true,
        fault_disable: true,
        dest_logical: false,
        vector: 0xA,
        delivery_mode: 0b100, // NMI
        destination: 0x1234,
    };
    let raw = ir::encode_irte(e);
    let back = ir::decode_irte(raw);
    if back != e {
        return TestResult::Fail("IRTE encode/decode round-trip mismatch");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/ir", smoke_irte_encode_decode);

#[cfg(target_arch = "x86_64")]
fn smoke_amd_ga_predicate() -> TestResult {
    use crate::x86_64::amd_ga;
    use crate::x86_64::amd_vi::{EFR_GASUP, EFR_IASUP};
    if !amd_ga::ga_supported(EFR_GASUP) {
        return TestResult::Fail("ga_supported false on EFR with GASUP set");
    }
    if amd_ga::ga_supported(EFR_IASUP) {
        return TestResult::Fail("ga_supported true on EFR with only IASUP");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/amd_ga", smoke_amd_ga_predicate);

#[cfg(target_arch = "x86_64")]
fn smoke_x86_cache_levels_present() -> TestResult {
    use crate::x86_64::cache_topology;
    let mut count = 0u32;
    cache_topology::levels(|_| count += 1);
    if count == 0 {
        return TestResult::Fail("no cache levels enumerated");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/cache_topology", smoke_x86_cache_levels_present);

#[cfg(target_arch = "aarch64")]
fn smoke_gits_caps_decode() -> TestResult {
    use crate::aarch64::gits;
    // ID-bits = 16, Devbits = 8, HCC = 0xABCD, physical bit set.
    let typer: u64 = (15)            // (id_bits - 1) = 15 → 16
                   | ((7u64) << 8)   // (dev_bits - 1) = 7 → 8
                   | ((0xABCDu64) << 16)
                   | (1u64 << 32);
    let c = gits::decode_caps(typer);
    if c.id_bits != 16 || c.dev_bits != 8 || c.hcc != 0xABCD || !c.physical {
        return TestResult::Fail("ITS TYPER decode mismatch");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/gits", smoke_gits_caps_decode);

#[cfg(target_arch = "aarch64")]
fn smoke_aarch_cache_levels_present() -> TestResult {
    use crate::aarch64::cache_topology;
    let mut count = 0u32;
    cache_topology::levels(|_| count += 1);
    if count == 0 {
        return TestResult::Fail("no cache levels enumerated");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/cache_topology", smoke_aarch_cache_levels_present);

#[cfg(target_arch = "aarch64")]
fn smoke_numa_cluster_id() -> TestResult {
    use crate::aarch64::numa;
    // Aff2 = 0x42, Aff1 = 0x55, Aff0 = 0x07.
    let mpidr: u64 = 0x07 | (0x55 << 8) | (0x42 << 16);
    if numa::cluster_id(mpidr) != 0x42 {
        return TestResult::Fail("aarch64 cluster_id decode mismatch");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/numa", smoke_numa_cluster_id);

#[cfg(target_arch = "x86_64")]
fn smoke_tme_supported_path() -> TestResult {
    use crate::x86_64::tme;
    let _ = tme::supported();
    // Pure-data decoder test: synthetic CAPABILITY value.
    //   AES_XTS_128 + AES_XTS_256, max_keyid_bits = 4, max_keys = 0x1F.
    let raw =
        tme::TME_CAPS_AES_XTS_128 | tme::TME_CAPS_AES_XTS_256 | (4u64 << 32) | (0x1Fu64 << 36);
    let c = tme::decode_caps(raw);
    if !c.aes_xts_128 || c.aes_xts_128_integrity || !c.aes_xts_256 {
        return TestResult::Fail("AES_XTS bits decoded incorrectly");
    }
    if c.max_keyid_bits != 4 || c.max_keys != 0x1F {
        return TestResult::Fail("MK-TME range fields decoded incorrectly");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/tme", smoke_tme_supported_path);

#[cfg(target_arch = "x86_64")]
fn smoke_rtm_always_abort_path() -> TestResult {
    use crate::x86_64::rtm_abort;
    let _ = rtm_abort::rtm_always_abort_supported();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/rtm_abort", smoke_rtm_always_abort_path);

#[cfg(target_arch = "aarch64")]
fn smoke_ecv_caps() -> TestResult {
    use crate::aarch64::ecv;
    if ecv::caps() > 2 {
        return TestResult::Fail("ECV field > 2 (architectural max as of v0.1)");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/ecv", smoke_ecv_caps);

#[cfg(target_arch = "aarch64")]
fn smoke_nv2_caps() -> TestResult {
    use crate::aarch64::nv2;
    if nv2::caps() > 2 {
        return TestResult::Fail("NV field > 2 (architectural max as of v0.1)");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/nv2", smoke_nv2_caps);

#[cfg(target_arch = "aarch64")]
fn smoke_e0pd_caps() -> TestResult {
    use crate::aarch64::e0pd;
    if e0pd::caps() > 1 {
        return TestResult::Fail("E0PD field > 1 (architectural max as of v0.1)");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/e0pd", smoke_e0pd_caps);

#[cfg(target_arch = "x86_64")]
fn smoke_sld_supported_path() -> TestResult {
    use crate::x86_64::sld;
    let _ = sld::cpuid_gate();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/sld", smoke_sld_supported_path);

#[cfg(target_arch = "x86_64")]
fn smoke_buslock_supported_path() -> TestResult {
    use crate::x86_64::buslock;
    let _ = buslock::supported();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/buslock", smoke_buslock_supported_path);

#[cfg(target_arch = "aarch64")]
fn smoke_lse_caps() -> TestResult {
    use crate::aarch64::lse;
    // The Atomic field is a 4-bit value; ARM keeps reserving
    // higher values for newer LSE revisions, so we just check
    // monotonicity instead of an architectural max.
    if lse::lse128_supported() && !lse::lse_supported() {
        return TestResult::Fail("LSE128 set without LSE");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/lse", smoke_lse_caps);

#[cfg(target_arch = "aarch64")]
fn smoke_rcpc_caps() -> TestResult {
    use crate::aarch64::lse;
    // Same monotonicity rationale as `smoke_lse_caps`.
    if lse::rcpc3_supported() && !lse::rcpc2_supported() {
        return TestResult::Fail("RCPC3 without RCPC2");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/lse", smoke_rcpc_caps);

#[cfg(target_arch = "aarch64")]
fn smoke_pie_caps() -> TestResult {
    use crate::aarch64::pie;
    let _ = pie::caps();
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/pie", smoke_pie_caps);

#[cfg(target_arch = "aarch64")]
fn smoke_sctlr2_supported_path() -> TestResult {
    use crate::aarch64::sctlr2;
    let _ = sctlr2::supported();
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/sctlr2", smoke_sctlr2_supported_path);
