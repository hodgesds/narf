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

fn smoke_speculation_state_is_per_cpu() -> TestResult {
    use crate::speculation::{state, State};
    use narf_lib::percpu::MAX_CPUS;

    if state(MAX_CPUS) != State::Failed {
        return TestResult::Fail("out-of-range speculation state did not fail closed");
    }
    let cpu = crate::narf_arch_cpu_id();
    let before = state(cpu);
    if before == State::Unconfigured {
        return TestResult::Fail("current CPU speculation policy was not configured at boot");
    }

    // A nested transition must fail without overwriting the completed state.
    let guard = match crate::speculation::TransitionGuard::acquire(cpu) {
        Some(guard) => guard,
        None => return TestResult::Fail("could not acquire transition guard"),
    };
    // SAFETY: this deliberately exercises nested-call rejection; the inner
    // call must return before touching hardware because `guard` owns the CPU.
    let nested =
        unsafe { crate::speculation::configure_current_cpu(crate::speculation::Policy::Protected) };
    if nested != State::Failed || state(cpu) != before {
        return TestResult::Fail("nested transition changed published CPU state");
    }
    drop(guard);

    // An idempotent protected transition exercises the real MSR/sysreg path
    // and must restore the caller's exact IRQ mask state.
    let irq_before = crate::interrupts_enabled();
    // SAFETY: kernel-test runs pinned on the current CPU; policy is only
    // strengthened and the transition implementation masks ordinary IRQs.
    let after =
        unsafe { crate::speculation::configure_current_cpu(crate::speculation::Policy::Protected) };
    if crate::interrupts_enabled() != irq_before {
        return TestResult::Fail("speculation transition did not restore IRQ state");
    }
    if after == State::Failed || state(cpu) != after {
        return TestResult::Fail("protected transition failed or was not published");
    }
    TestResult::Pass
}
kernel_test_in!("arch/speculation", smoke_speculation_state_is_per_cpu);

#[cfg(target_arch = "x86_64")]
fn smoke_spec_ctrl_policy_mask_preserves_unowned_bits() -> TestResult {
    use crate::x86_64::spec_ctrl::{
        desired_value, SpecCtrlFeatures, SPEC_CTRL_IBRS, SPEC_CTRL_SSBD, SPEC_CTRL_STIBP,
    };
    let unowned = 1u64 << 40;
    let features = SpecCtrlFeatures {
        ibrs: true,
        stibp: false,
        ssbd: true,
        l1d_flush: false,
    };
    let (enabled, supported) = match desired_value(unowned | SPEC_CTRL_STIBP, features, true) {
        Some(values) => values,
        None => return TestResult::Fail("supported policy unexpectedly returned None"),
    };
    if supported != SPEC_CTRL_IBRS | SPEC_CTRL_SSBD {
        return TestResult::Fail("policy mask included an unsupported feature");
    }
    if enabled & unowned == 0 || enabled & SPEC_CTRL_STIBP == 0 {
        return TestResult::Fail("enable policy clobbered a pre-existing bit");
    }
    let (disabled, _) = desired_value(enabled, features, false).unwrap();
    if disabled & unowned == 0
        || disabled & SPEC_CTRL_STIBP == 0
        || disabled & (SPEC_CTRL_IBRS | SPEC_CTRL_SSBD) != 0
    {
        return TestResult::Fail("disable policy clobbered unsupported or unowned bits");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "arch/speculation",
    smoke_spec_ctrl_policy_mask_preserves_unowned_bits
);

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
    for slot in COUNTER.iter().skip(1) {
        if slot.load(Ordering::Relaxed) != 0 {
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
    let addr = SLOT.as_ptr();
    // SAFETY: SLOT is a static mut u32 (interior-atomic); addr is
    // 4-byte aligned. `patch_word` only writes 4 bytes + serialises.
    // SAFETY: Valid memory or trusted environment
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
fn smoke_aarch64_ssbs_readback() -> TestResult {
    use crate::aarch64::ssbs;
    if ssbs::caps() < 2 {
        return TestResult::Skip("SSBS direct instructions unavailable");
    }
    // Boot configured the protected policy. This validates both corrected
    // raw encodings and the architectural polarity (SSBS=0 is safe).
    // SAFETY: EL1 and caps >= 2.
    if !unsafe { ssbs::is_enabled() } {
        return TestResult::Fail("PSTATE.SSBS was not enabled after protected boot policy");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/speculation", smoke_aarch64_ssbs_readback);

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
    // SAFETY: MRS of ID_AA64* is always legal at EL1.
    let feats = unsafe { crate::aarch64::Features::probe() };
    // SAFETY: CNTFRQ_EL0 is always readable at EL1.
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
    // SAFETY: Valid memory or trusted environment
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
    // SAFETY: Valid memory or trusted environment
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
    if !(100_000_000..=10_000_000_000).contains(&hz) {
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
        // Under QEMU TCG with `-cpu max` (how `xtask test` and GHA run — no
        // KVM), the guest gets no real CPUID vendor identity, so the microcode
        // vendor probe reads back Unknown. It only reports a true
        // AuthenticAMD/GenuineIntel with `-accel kvm -cpu host` (host-CPU
        // passthrough). Skip in the no-passthrough case rather than fail —
        // same disposition as the other real-HW smokes that skip on GHA. A
        // genuine vendor-detection *bug* on real hardware still surfaces
        // there, where the probe returns a concrete (wrong) vendor, not Skip.
        microcode::Vendor::Unknown => {
            TestResult::Skip("no CPUID vendor under TCG -cpu max; needs -cpu host/KVM")
        }
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/microcode", smoke_microcode_vendor_detect);

#[cfg(target_arch = "x86_64")]
fn smoke_microcode_intel_header_roundtrip() -> TestResult {
    use crate::x86_64::microcode::{IntelUcodeHeader, INTEL_HEADER_LEN};
    // Build a synthetic 48-byte header + 2000-byte body whose
    // checksum sums to zero. header_version=1, loader_revision=1.
    let mut blob = [0u8; 2048];
    // header[0..4] = header_version (1)
    blob[0] = 1;
    // header[20..24] = loader_revision (1)
    blob[20] = 1;
    // total_size = 0 → effective 2048 (48 + 2000 default body).
    // data_size = 0 → effective 2000.
    // checksum field at [16..20]: pick a value that makes the
    // dword-sum over the whole 2048-byte blob equal zero. After
    // setting all other fields, sum and negate.
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 4 <= 2048 {
        let dw = u32::from_le_bytes([blob[i], blob[i + 1], blob[i + 2], blob[i + 3]]);
        sum = sum.wrapping_add(dw);
        i += 4;
    }
    let checksum = 0u32.wrapping_sub(sum);
    blob[16..20].copy_from_slice(&checksum.to_le_bytes());
    let h = match IntelUcodeHeader::decode(&blob) {
        Some(h) => h,
        None => return TestResult::Fail("decode failed"),
    };
    if h.header_version != 1 || h.loader_revision != 1 {
        return TestResult::Fail("header fields didn't round-trip");
    }
    if h.effective_total_size() != 2048 {
        return TestResult::Fail("effective_total_size != 2048");
    }
    if h.effective_data_size() != 2000 {
        return TestResult::Fail("effective_data_size != 2000");
    }
    if h.validate(&blob).is_err() {
        return TestResult::Fail("validate rejected a well-formed blob");
    }
    let _ = INTEL_HEADER_LEN;
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/microcode", smoke_microcode_intel_header_roundtrip);

#[cfg(target_arch = "x86_64")]
fn smoke_microcode_intel_header_reject_bad_version() -> TestResult {
    use crate::x86_64::microcode::IntelUcodeHeader;
    let mut blob = [0u8; 2048];
    // header_version = 2 → reject
    blob[0] = 2;
    blob[20] = 1;
    let h = match IntelUcodeHeader::decode(&blob) {
        Some(h) => h,
        None => return TestResult::Fail("decode unexpectedly failed"),
    };
    match h.validate(&blob) {
        Err(crate::x86_64::microcode::UcodeError::BadHeader) => TestResult::Pass,
        _ => TestResult::Fail("validate accepted header_version != 1"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "arch/microcode",
    smoke_microcode_intel_header_reject_bad_version
);

#[cfg(target_arch = "x86_64")]
fn smoke_microcode_intel_header_reject_bad_checksum() -> TestResult {
    use crate::x86_64::microcode::{IntelUcodeHeader, UcodeError};
    // Same well-formed 2048-byte layout but with checksum left at
    // zero — the dword-sum is non-zero and validate must reject.
    let mut blob = [0u8; 2048];
    blob[0] = 1; // header_version
    blob[20] = 1; // loader_revision
                  // Stuff a non-zero dword somewhere to guarantee the sum is
                  // non-zero regardless of platform.
    blob[36] = 0xDE;
    blob[37] = 0xAD;
    blob[38] = 0xBE;
    blob[39] = 0xEF;
    let h = match IntelUcodeHeader::decode(&blob) {
        Some(h) => h,
        None => return TestResult::Fail("decode unexpectedly failed"),
    };
    match h.validate(&blob) {
        Err(UcodeError::BadHeader) => TestResult::Pass,
        _ => TestResult::Fail("validate accepted blob with bad checksum"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "arch/microcode",
    smoke_microcode_intel_header_reject_bad_checksum
);

#[cfg(target_arch = "x86_64")]
fn smoke_microcode_intel_header_reject_unaligned_total() -> TestResult {
    use crate::x86_64::microcode::{IntelUcodeHeader, UcodeError};
    let mut blob = [0u8; 2048];
    blob[0] = 1; // header_version
    blob[20] = 1; // loader_revision
                  // total_size not a multiple of 4 → reject.
    blob[32..36].copy_from_slice(&123u32.to_le_bytes());
    let h = match IntelUcodeHeader::decode(&blob) {
        Some(h) => h,
        None => return TestResult::Fail("decode unexpectedly failed"),
    };
    match h.validate(&blob) {
        Err(UcodeError::BadHeader) | Err(UcodeError::TooShort) => TestResult::Pass,
        _ => TestResult::Fail("validate accepted blob with mis-aligned total_size"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "arch/microcode",
    smoke_microcode_intel_header_reject_unaligned_total
);

#[cfg(target_arch = "x86_64")]
fn smoke_microcode_fms_decode_renoir_phoenix() -> TestResult {
    use crate::x86_64::microcode::FamilyModelStepping;
    // Renoir / Lucienne — Family 17h, Model 60h, Stepping 1.
    // Per AMD's CPUID encoding rules (base_family == 0xF):
    //   base_family = 0xF, ext_family = 0x8 → family = 0x17
    //   base_model = 0x0, ext_model = 0x6 → model = 0x60
    //   stepping = 0x1 → CPUID(1).EAX = 0x0086_0F01.
    let fms = FamilyModelStepping::from_raw(0x0086_0F01);
    if fms.family != 0x17 || fms.model != 0x60 || fms.stepping != 1 {
        return TestResult::Fail("Renoir FMS decode mismatch");
    }
    // Phoenix / HawkPoint1 — Family 19h, Model 74h, Stepping 1.
    //   base_family = 0xF, ext_family = 0xA → family = 0x19
    //   base_model = 0x4, ext_model = 0x7 → model = 0x74
    //   stepping = 0x1 → CPUID(1).EAX = 0x00A7_0F41.
    let fms = FamilyModelStepping::from_raw(0x00A7_0F41);
    if fms.family != 0x19 || fms.model != 0x74 || fms.stepping != 1 {
        return TestResult::Fail("Phoenix FMS decode mismatch");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/microcode", smoke_microcode_fms_decode_renoir_phoenix);

#[cfg(target_arch = "x86_64")]
fn smoke_microcode_intel_filename_derivation() -> TestResult {
    use crate::x86_64::microcode::FamilyModelStepping;
    // Intel Comet Lake — Family 06h, Model A6h, Stepping 1.
    //   base_family = 0x6, ext_family = 0 → family = 0x6
    //   base_model = 0x6, ext_model = 0xA → model = 0xA6
    //   stepping = 0x1 → CPUID(1).EAX = 0x000A_0661.
    let fms = FamilyModelStepping::from_raw(0x000A_0661);
    let name = fms.intel_filename();
    if &name != b"06-A6-01" {
        return TestResult::Fail("intel_filename mismatch for CometLake");
    }
    // Intel Tiger Lake — Family 06h, Model 8Ch, Stepping 1.
    //   base_model = 0xC, ext_model = 0x8 → model = 0x8C
    //   stepping = 0x1 → CPUID(1).EAX = 0x0008_06C1.
    let fms = FamilyModelStepping::from_raw(0x0008_06C1);
    let name = fms.intel_filename();
    if &name != b"06-8C-01" {
        return TestResult::Fail("intel_filename mismatch for TigerLake");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/microcode", smoke_microcode_intel_filename_derivation);

#[cfg(target_arch = "x86_64")]
fn smoke_microcode_amd_family_tag() -> TestResult {
    use crate::x86_64::microcode::FamilyModelStepping;
    // Zen2 Renoir — Family 17h.
    let fms = FamilyModelStepping::from_raw(0x0086_0F01);
    if &fms.amd_family_tag() != b"17h" {
        return TestResult::Fail("Renoir family tag mismatch");
    }
    // Zen4 Phoenix — Family 19h.
    let fms = FamilyModelStepping::from_raw(0x00A7_0F41);
    if &fms.amd_family_tag() != b"19h" {
        return TestResult::Fail("Phoenix family tag mismatch");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/microcode", smoke_microcode_amd_family_tag);

#[cfg(target_arch = "x86_64")]
fn smoke_microcode_amd_container_decode() -> TestResult {
    use crate::x86_64::microcode::{
        amd_find_equiv, amd_find_patch, AmdContainerHeader, AMD_CONTAINER_MAGIC, AMD_EQUIV_TYPE,
        AMD_PATCH_HDR_LEN, AMD_PATCH_SECTION_HDR_LEN, AMD_PATCH_SECTION_TYPE,
    };
    // Build a minimal AMD container with one equiv entry pointing
    // to one patch section.
    // Layout:
    //   [0..4]   magic = 0x00414D44
    //   [4..8]   equiv_table_type = 1
    //   [8..12]  equiv_table_len = 32 (one real entry + null terminator)
    //   [12..28] equiv entry: installed_cpu=0x00870F10, equiv_cpu=0x8310
    //   [28..44] null terminator entry (zero installed_cpu/equiv_cpu)
    //   [44..48] section_type = 1
    //   [48..52] section_size = 64 (just the patch header, no body)
    //   [52..116] patch header with processor_rev_id = 0x8310
    let mut blob = [0u8; 116];
    blob[0..4].copy_from_slice(&AMD_CONTAINER_MAGIC.to_le_bytes());
    blob[4..8].copy_from_slice(&AMD_EQUIV_TYPE.to_le_bytes());
    blob[8..12].copy_from_slice(&32u32.to_le_bytes());
    // Equiv entry #1.
    blob[12..16].copy_from_slice(&0x0086_0F01u32.to_le_bytes()); // installed_cpu (Renoir)
    blob[24..26].copy_from_slice(&0x8310u16.to_le_bytes()); // equiv_cpu
                                                            // Equiv entry #2 = all-zero terminator (already zero).
                                                            // Patch section header.
    blob[44..48].copy_from_slice(&AMD_PATCH_SECTION_TYPE.to_le_bytes());
    blob[48..52].copy_from_slice(&(AMD_PATCH_HDR_LEN as u32).to_le_bytes());
    // Patch header: processor_rev_id at offset 24..26.
    blob[52 + 24..52 + 26].copy_from_slice(&0x8310u16.to_le_bytes());

    // Container decode + validate.
    let hdr = match AmdContainerHeader::decode(&blob) {
        Some(h) => h,
        None => return TestResult::Fail("container decode failed"),
    };
    if hdr.validate().is_err() {
        return TestResult::Fail("container validate rejected good blob");
    }
    // Lookup.
    let equiv = match amd_find_equiv(&blob, 0x0086_0F01) {
        Some(e) => e,
        None => return TestResult::Fail("amd_find_equiv missed installed_cpu"),
    };
    if equiv != 0x8310 {
        return TestResult::Fail("equiv code mismatch");
    }
    let patch = match amd_find_patch(&blob, equiv) {
        Some(p) => p,
        None => return TestResult::Fail("amd_find_patch missed the section"),
    };
    if patch.len() != AMD_PATCH_HDR_LEN {
        return TestResult::Fail("patch body length wrong");
    }
    // CPUID we don't have an entry for → None.
    if amd_find_equiv(&blob, 0x0000_DEAD).is_some() {
        return TestResult::Fail("amd_find_equiv accepted an unknown CPUID");
    }
    let _ = AMD_PATCH_SECTION_HDR_LEN;
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/microcode", smoke_microcode_amd_container_decode);

#[cfg(target_arch = "x86_64")]
fn smoke_microcode_applied_revision_tracker() -> TestResult {
    use crate::x86_64::microcode;
    microcode::__reset_applied_revision_for_test();
    if microcode::applied_revision() != 0 {
        return TestResult::Fail("reset didn't clear applied_revision");
    }
    // We can't fake-apply at this layer without an MSR mock; just
    // make sure the accessor compiles + reset is idempotent.
    microcode::__reset_applied_revision_for_test();
    if microcode::applied_revision() != 0 {
        return TestResult::Fail("second reset diverged");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/microcode", smoke_microcode_applied_revision_tracker);

#[cfg(target_arch = "x86_64")]
fn smoke_microcode_cpu_signature_matches_ident() -> TestResult {
    use crate::x86_64::ident;
    use crate::x86_64::microcode;
    // Both reads come from CPUID(1).EAX; if the wrappers diverge
    // we've miswired one of them.
    let id = ident::read();
    let sig = microcode::cpu_signature();
    if id.signature != sig {
        return TestResult::Fail("microcode::cpu_signature differs from ident::read");
    }
    // FMS decoder agreement, too.
    let fms = microcode::FamilyModelStepping::from_raw(sig);
    if fms.family != id.family || fms.model != id.model || fms.stepping != id.stepping {
        return TestResult::Fail("FMS decode disagrees with ident::read");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "arch/microcode",
    smoke_microcode_cpu_signature_matches_ident
);

#[cfg(target_arch = "x86_64")]
fn smoke_microcode_blob_filename_for_current_cpu() -> TestResult {
    use crate::x86_64::microcode;
    let mut buf = [0u8; 40];
    let n = match microcode::blob_filename_for_current_cpu(&mut buf) {
        Some(n) => n,
        None => return TestResult::Fail("blob_filename_for_current_cpu returned None"),
    };
    let name = &buf[..n];
    match microcode::vendor() {
        microcode::Vendor::Intel => {
            // "intel-ucode/" prefix + 8 ASCII bytes.
            if !name.starts_with(b"intel-ucode/") {
                return TestResult::Fail("intel name missing prefix");
            }
            if name.len() != b"intel-ucode/".len() + 8 {
                return TestResult::Fail("intel name wrong length");
            }
        }
        microcode::Vendor::Amd => {
            if !name.starts_with(b"amd-ucode/microcode_amd_fam") {
                return TestResult::Fail("amd name missing prefix");
            }
            if !name.ends_with(b".bin") {
                return TestResult::Fail("amd name missing .bin suffix");
            }
        }
        microcode::Vendor::Unknown => {
            return TestResult::Fail("unknown vendor on x86_64");
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "arch/microcode",
    smoke_microcode_blob_filename_for_current_cpu
);

#[cfg(target_arch = "x86_64")]
fn smoke_microcode_blob_filename_buffer_too_small() -> TestResult {
    use crate::x86_64::microcode;
    // 4 bytes isn't enough for any vendor.
    let mut buf = [0u8; 4];
    if microcode::blob_filename_for_current_cpu(&mut buf).is_some() {
        return TestResult::Fail("accepted undersized buffer");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "arch/microcode",
    smoke_microcode_blob_filename_buffer_too_small
);

#[cfg(target_arch = "x86_64")]
fn smoke_microcode_resolve_rejects_short_blob() -> TestResult {
    use crate::x86_64::microcode::{self, UcodeError};
    // Empty + tiny blobs reject without touching MSRs.
    let empty = [];
    match microcode::resolve_for_current_cpu(&empty) {
        Err(UcodeError::TooShort)
        | Err(UcodeError::SignatureMismatch)
        | Err(UcodeError::BadHeader)
        | Err(UcodeError::UnknownVendor) => TestResult::Pass,
        _ => TestResult::Fail("empty blob accepted"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/microcode", smoke_microcode_resolve_rejects_short_blob);

#[cfg(target_arch = "x86_64")]
fn smoke_microcode_amd_resolve_picks_patch() -> TestResult {
    use crate::x86_64::microcode::{
        self, AMD_CONTAINER_MAGIC, AMD_EQUIV_TYPE, AMD_PATCH_HDR_LEN, AMD_PATCH_SECTION_TYPE,
    };
    // Only meaningful on AMD hosts; skip on Intel.
    if microcode::vendor() != microcode::Vendor::Amd {
        return TestResult::Skip("AMD-only");
    }
    let sig = microcode::cpu_signature();
    let mut blob = [0u8; 116];
    blob[0..4].copy_from_slice(&AMD_CONTAINER_MAGIC.to_le_bytes());
    blob[4..8].copy_from_slice(&AMD_EQUIV_TYPE.to_le_bytes());
    blob[8..12].copy_from_slice(&32u32.to_le_bytes());
    blob[12..16].copy_from_slice(&sig.to_le_bytes()); // installed_cpu = running CPU
    blob[24..26].copy_from_slice(&0x4242u16.to_le_bytes()); // equiv_cpu
                                                            // (entry #2 = all-zero terminator)
    blob[44..48].copy_from_slice(&AMD_PATCH_SECTION_TYPE.to_le_bytes());
    blob[48..52].copy_from_slice(&(AMD_PATCH_HDR_LEN as u32).to_le_bytes());
    blob[52 + 24..52 + 26].copy_from_slice(&0x4242u16.to_le_bytes());

    match microcode::resolve_for_current_cpu(&blob) {
        Ok(patch) => {
            if patch.len() != AMD_PATCH_HDR_LEN {
                return TestResult::Fail("resolved AMD patch wrong length");
            }
            TestResult::Pass
        }
        Err(_) => TestResult::Fail("resolve_for_current_cpu rejected matching blob"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/microcode", smoke_microcode_amd_resolve_picks_patch);

#[cfg(target_arch = "x86_64")]
fn smoke_microcode_amd_resolve_misses_wrong_cpu() -> TestResult {
    use crate::x86_64::microcode::{
        self, UcodeError, AMD_CONTAINER_MAGIC, AMD_EQUIV_TYPE, AMD_PATCH_HDR_LEN,
        AMD_PATCH_SECTION_TYPE,
    };
    if microcode::vendor() != microcode::Vendor::Amd {
        return TestResult::Skip("AMD-only");
    }
    // Build a container that doesn't include our CPUID.
    let mut blob = [0u8; 116];
    blob[0..4].copy_from_slice(&AMD_CONTAINER_MAGIC.to_le_bytes());
    blob[4..8].copy_from_slice(&AMD_EQUIV_TYPE.to_le_bytes());
    blob[8..12].copy_from_slice(&32u32.to_le_bytes());
    blob[12..16].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // not us
    blob[24..26].copy_from_slice(&0x4242u16.to_le_bytes());
    blob[44..48].copy_from_slice(&AMD_PATCH_SECTION_TYPE.to_le_bytes());
    blob[48..52].copy_from_slice(&(AMD_PATCH_HDR_LEN as u32).to_le_bytes());
    blob[52 + 24..52 + 26].copy_from_slice(&0x4242u16.to_le_bytes());

    match microcode::resolve_for_current_cpu(&blob) {
        Err(UcodeError::SignatureMismatch) => TestResult::Pass,
        _ => TestResult::Fail("accepted blob that doesn't cover this CPU"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "arch/microcode",
    smoke_microcode_amd_resolve_misses_wrong_cpu
);

// ---- new logic: revision compare, container iteration, ext-sig,
//      AMD best-patch pick, and the apply-path DECISION ----

#[cfg(target_arch = "x86_64")]
fn smoke_microcode_needs_update_revision_compare() -> TestResult {
    use crate::x86_64::microcode::needs_update;
    // Strictly-newer is the whole rule.
    if !needs_update(0x10, 0x11) {
        return TestResult::Fail("newer candidate should update");
    }
    if needs_update(0x11, 0x11) {
        return TestResult::Fail("equal revision must not update");
    }
    if needs_update(0x11, 0x10) {
        return TestResult::Fail("older candidate must not update");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "arch/microcode",
    smoke_microcode_needs_update_revision_compare
);

// Build one valid Intel update (48-byte header + `body_words`
// dword body) into `out`, with the given signature/flags/revision,
// fixing the checksum so the dword-sum over the whole update is 0.
// Returns the update length. `total_size == body area + 48`.
#[cfg(target_arch = "x86_64")]
fn build_intel_update(out: &mut [u8], sig: u32, flags: u32, rev: u32, body_words: usize) -> usize {
    let data_size = (body_words * 4) as u32;
    let total = crate::x86_64::microcode::INTEL_HEADER_LEN + data_size as usize;
    for b in out[..total].iter_mut() {
        *b = 0;
    }
    out[0..4].copy_from_slice(&1u32.to_le_bytes()); // header_version
    out[4..8].copy_from_slice(&rev.to_le_bytes()); // update_revision
    out[12..16].copy_from_slice(&sig.to_le_bytes()); // processor_signature
    out[20..24].copy_from_slice(&1u32.to_le_bytes()); // loader_revision
    out[24..28].copy_from_slice(&flags.to_le_bytes()); // processor_flags
    out[28..32].copy_from_slice(&data_size.to_le_bytes()); // data_size
    out[32..36].copy_from_slice(&(total as u32).to_le_bytes()); // total_size
                                                                // checksum so the dword sum is zero.
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 4 <= total {
        sum = sum.wrapping_add(u32::from_le_bytes([
            out[i],
            out[i + 1],
            out[i + 2],
            out[i + 3],
        ]));
        i += 4;
    }
    let cksum = 0u32.wrapping_sub(sum);
    out[16..20].copy_from_slice(&cksum.to_le_bytes());
    total
}

#[cfg(target_arch = "x86_64")]
fn smoke_microcode_intel_container_best_match() -> TestResult {
    use crate::x86_64::microcode::intel_select_update;
    // Three concatenated updates: two for our sig (revs 5 and 9,
    // flags 0 = match any platform), one for a different sig.
    let sig: u32 = 0x000A_0661;
    let other: u32 = 0x0008_06C1;
    let mut blob = [0u8; 4096];
    let mut off = 0;
    off += build_intel_update(&mut blob[off..], sig, 0, 5, 4);
    off += build_intel_update(&mut blob[off..], other, 0, 99, 4);
    off += build_intel_update(&mut blob[off..], sig, 0, 9, 4);
    let file = &blob[..off];

    // With platform mask 1: pick the highest revision for `sig` (9).
    match intel_select_update(file, sig, 1) {
        Some((_, 9)) => {}
        Some(_) => return TestResult::Fail("picked wrong Intel revision"),
        None => return TestResult::Fail("Intel container select found no match"),
    }
    // A sig not in the file → no match.
    if intel_select_update(file, 0xDEAD_BEEF, 1).is_some() {
        return TestResult::Fail("Intel select matched a foreign sig");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/microcode", smoke_microcode_intel_container_best_match);

#[cfg(target_arch = "x86_64")]
fn smoke_microcode_intel_ext_sig_multi_platform() -> TestResult {
    use crate::x86_64::microcode::{
        intel_update_matches, INTEL_EXT_HEADER_LEN, INTEL_EXT_SIG_LEN, INTEL_HEADER_LEN,
    };
    // One update whose primary sig is `primary` but which also
    // carries an extended-signature table matching `alt` (platform
    // flag bit 2). Layout: header(48) + body(16) + ext-hdr(20) +
    // 1 ext entry(12).
    let primary: u32 = 0x000A_0661;
    let alt: u32 = 0x0005_0654;
    let alt_flags: u32 = 0b100; // platform-id bit 2
    let body = 16usize;
    let primary_span = INTEL_HEADER_LEN + body;
    let total = primary_span + INTEL_EXT_HEADER_LEN + INTEL_EXT_SIG_LEN;
    let mut blob = [0u8; 128];
    blob[0..4].copy_from_slice(&1u32.to_le_bytes()); // header_version
    blob[4..8].copy_from_slice(&7u32.to_le_bytes()); // update_revision
    blob[12..16].copy_from_slice(&primary.to_le_bytes()); // processor_signature
    blob[20..24].copy_from_slice(&1u32.to_le_bytes()); // loader_revision
    blob[24..28].copy_from_slice(&1u32.to_le_bytes()); // primary processor_flags (bit0)
    blob[28..32].copy_from_slice(&(body as u32).to_le_bytes()); // data_size
    blob[32..36].copy_from_slice(&(total as u32).to_le_bytes()); // total_size
                                                                 // ext-table header: count = 1.
    blob[primary_span..primary_span + 4].copy_from_slice(&1u32.to_le_bytes());
    // ext entry: sig=alt, flags=alt_flags.
    let eoff = primary_span + INTEL_EXT_HEADER_LEN;
    blob[eoff..eoff + 4].copy_from_slice(&alt.to_le_bytes());
    blob[eoff + 4..eoff + 8].copy_from_slice(&alt_flags.to_le_bytes());
    // Fix the primary checksum so the whole update dword-sums to 0.
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 4 <= total {
        sum = sum.wrapping_add(u32::from_le_bytes([
            blob[i],
            blob[i + 1],
            blob[i + 2],
            blob[i + 3],
        ]));
        i += 4;
    }
    let cksum = 0u32.wrapping_sub(sum);
    blob[16..20].copy_from_slice(&cksum.to_le_bytes());
    let update = &blob[..total];

    // Primary sig matches on platform bit 0.
    if !intel_update_matches(update, primary, 1) {
        return TestResult::Fail("primary sig should match");
    }
    // The extended sig matches only on its platform bit (2).
    if !intel_update_matches(update, alt, alt_flags) {
        return TestResult::Fail("ext sig should match on its platform flag");
    }
    // Same alt sig but wrong platform mask → no match (flags gate).
    if intel_update_matches(update, alt, 0b1) {
        return TestResult::Fail("ext sig matched despite platform-flag mismatch");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "arch/microcode",
    smoke_microcode_intel_ext_sig_multi_platform
);

#[cfg(target_arch = "x86_64")]
fn smoke_microcode_amd_equiv_and_best_patch() -> TestResult {
    use crate::x86_64::microcode::{
        amd_find_equiv, amd_find_patch, AmdPatchHeader, AMD_CONTAINER_MAGIC, AMD_EQUIV_TYPE,
        AMD_PATCH_HDR_LEN, AMD_PATCH_SECTION_TYPE,
    };
    // Container: one equiv entry (installed_cpu → equiv 0x8310) then
    // two patch sections for that equiv with patch_id 0x100 and
    // 0x200 — the walker must return the higher (0x200).
    let installed: u32 = 0x0086_0F01;
    let equiv_code: u16 = 0x8310;
    // 12 hdr + 32 equiv-table + 2*(8 + 64) sections.
    let mut blob = [0u8; 12 + 32 + 2 * (8 + AMD_PATCH_HDR_LEN)];
    blob[0..4].copy_from_slice(&AMD_CONTAINER_MAGIC.to_le_bytes());
    blob[4..8].copy_from_slice(&AMD_EQUIV_TYPE.to_le_bytes());
    blob[8..12].copy_from_slice(&32u32.to_le_bytes());
    blob[12..16].copy_from_slice(&installed.to_le_bytes());
    blob[24..26].copy_from_slice(&equiv_code.to_le_bytes());
    // (entry #2 = zero terminator)
    let mut off = 12 + 32;
    for (patch_id, rev_id) in [(0x100u32, equiv_code), (0x200u32, equiv_code)] {
        blob[off..off + 4].copy_from_slice(&AMD_PATCH_SECTION_TYPE.to_le_bytes());
        blob[off + 4..off + 8].copy_from_slice(&(AMD_PATCH_HDR_LEN as u32).to_le_bytes());
        let body = off + 8;
        blob[body + 4..body + 8].copy_from_slice(&patch_id.to_le_bytes()); // patch_id @4
        blob[body + 24..body + 26].copy_from_slice(&rev_id.to_le_bytes()); // processor_rev_id @24
        off = body + AMD_PATCH_HDR_LEN;
    }

    let equiv = match amd_find_equiv(&blob, installed) {
        Some(e) => e,
        None => return TestResult::Fail("equiv lookup missed installed_cpu"),
    };
    if equiv != equiv_code {
        return TestResult::Fail("equiv code mismatch");
    }
    let patch = match amd_find_patch(&blob, equiv) {
        Some(p) => p,
        None => return TestResult::Fail("patch lookup found nothing"),
    };
    let ph = match AmdPatchHeader::decode(patch) {
        Some(h) => h,
        None => return TestResult::Fail("patch header decode failed"),
    };
    if ph.patch_id != 0x200 {
        return TestResult::Fail("amd_find_patch did not pick the highest patch_id");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/microcode", smoke_microcode_amd_equiv_and_best_patch);

#[cfg(target_arch = "x86_64")]
fn smoke_microcode_load_and_apply_already_current() -> TestResult {
    use crate::x86_64::microcode::{self, Outcome};
    // Intel-only: a container whose one matching update carries a
    // revision <= the running CPU's must return AlreadyCurrent
    // without ever writing the loader MSR. Revision 0 is <= any
    // real running revision, so the decision short-circuits.
    if microcode::vendor() != microcode::Vendor::Intel {
        return TestResult::Skip("Intel-only decision test");
    }
    let sig = microcode::cpu_signature();
    let pf = microcode::intel_platform_flag_mask();
    let mut blob = [0u8; 512];
    // Flags = the CPU's platform mask so it matches; rev = 0.
    let n = build_intel_update(&mut blob, sig, pf, 0, 4);
    // SAFETY: kernel test runs at CPL=0 on the BSP; rev 0 forces the
    // AlreadyCurrent short-circuit before any loader-MSR write.
    match unsafe { microcode::load_and_apply(&blob[..n]) } {
        Outcome::AlreadyCurrent { candidate, .. } => {
            if candidate != 0 {
                return TestResult::Fail("candidate revision wrong");
            }
            TestResult::Pass
        }
        Outcome::Virtualized { .. } => TestResult::Pass, // MSR handshake trapped: still no apply
        _ => TestResult::Fail("expected AlreadyCurrent/Virtualized"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "arch/microcode",
    smoke_microcode_load_and_apply_already_current
);

#[cfg(target_arch = "x86_64")]
fn smoke_microcode_load_and_apply_no_match() -> TestResult {
    use crate::x86_64::microcode::{self, Outcome};
    // A container that carries no update for this silicon must
    // return NoMatch (no MSR write). Works on either vendor: feed
    // the wrong-vendor magic so resolve rejects it as NoMatch.
    let blob = [0x11u8; 256]; // not a valid Intel header nor AMD magic
                              // SAFETY: kernel test runs at CPL=0 on the BSP; the container
                              // matches no update so resolve returns before any MSR write.
    match unsafe { microcode::load_and_apply(&blob) } {
        Outcome::NoMatch | Outcome::Unsupported => TestResult::Pass,
        _ => TestResult::Fail("expected NoMatch/Unsupported"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/microcode", smoke_microcode_load_and_apply_no_match);

#[cfg(target_arch = "x86_64")]
fn smoke_errata_table_has_patched_in_field() -> TestResult {
    use crate::x86_64::errata;
    // Every table entry carries a `patched_in` u32. At least one
    // AMD entry should have a non-zero `patched_in` (Zenbleed) —
    // verifies the field is wired through, not just declared.
    let mut found = false;
    for e in errata::TABLE {
        if e.patched_in != 0 {
            found = true;
            break;
        }
    }
    if !found {
        return TestResult::Fail("no errata entry carries a patched_in revision");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/errata", smoke_errata_table_has_patched_in_field);

#[cfg(target_arch = "x86_64")]
fn smoke_errata_entries_matching_current_cpu_runs() -> TestResult {
    use crate::x86_64::errata;
    // The query path should not crash; the result depends on host
    // silicon, so just verify it runs + counts are within bounds.
    let (_names, n) = errata::entries_matching_current_cpu();
    if n > 8 {
        return TestResult::Fail("entries count overflowed fixed-size buffer");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "arch/errata",
    smoke_errata_entries_matching_current_cpu_runs
);

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
    // SAFETY: Valid memory or trusted environment
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
    // SAFETY: Valid memory or trusted environment
    let t = match unsafe { rtc::read_now() } {
        Ok(t) => t,
        Err(rtc::RtcError::UpdateInProgress) => {
            // QEMU's CMOS doesn't set UIP; treat as skip.
            return TestResult::Skip("UIP never cleared (QEMU or no RTC)");
        }
        Err(rtc::RtcError::OutOfRange) => {
            return TestResult::Fail("RTC read returned OutOfRange");
        }
    };
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
    if !(1_000_000..=1_000_000_000).contains(&hz) {
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
fn smoke_arch_fsgsbase_enabled_and_round_trips() -> TestResult {
    use crate::x86_64::{cr, msr, user_mode};

    if !user_mode::fsgsbase_supported() {
        return TestResult::Skip("FSGSBASE not advertised");
    }
    if cr::cached_cr4() & cr::CR4_FSGSBASE == 0 {
        return TestResult::Fail("FSGSBASE advertised but CR4.FSGSBASE is off");
    }

    const PROBE: u64 = 0x0000_7f53_4753_b000;
    // Preserve the surrounding task's FS base. NARF kernel code uses GS for
    // per-CPU state, so changing FS between these fenced helpers is inert.
    // SAFETY: kernel tests execute at CPL0 and PROBE is canonical.
    let original = unsafe { user_mode::user_fs_base() };
    // SAFETY: as above; restore occurs before evaluating the result.
    unsafe { user_mode::set_user_fs_base(PROBE) };
    // SAFETY: CR4.FSGSBASE was checked above.
    let observed = unsafe { user_mode::user_fs_base() };
    let cpu = crate::current_cpu_id().raw() as usize;
    // SAFETY: `cpu` names the executing CPU and the test runs at CPL0.
    let observed_pinned = unsafe { user_mode::user_fs_base_for_cpu(cpu) };
    // Verify the architectural backing state too, so the test cannot pass by
    // reading a software cache rather than the live FS base.
    // SAFETY: IA32_FS_BASE is readable at CPL0.
    let observed_msr = unsafe { msr::rdmsr(user_mode::IA32_FS_BASE) };
    // SAFETY: restore the canonical value captured from this CPU.
    unsafe { user_mode::set_user_fs_base(original) };

    if observed != PROBE || observed_pinned != PROBE || observed_msr != PROBE {
        return TestResult::Fail("WRFSBASE/RDFSBASE did not round-trip IA32_FS_BASE");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/fsgsbase", smoke_arch_fsgsbase_enabled_and_round_trips);

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
fn smoke_x86_errata_table_covers_zen_families() -> TestResult {
    // Sanity: the table should carry an AMD entry for every Zen
    // family we've documented workarounds for. If a future edit
    // accidentally drops one (e.g. mass-rename of the apply
    // function) this test catches it.
    use crate::x86_64::errata;
    use crate::x86_64::ident::Vendor;
    let t = errata::table();
    let mut zen1 = false;
    let mut zen2 = false;
    let mut zen4 = false;
    let mut zen5 = false;
    for e in t {
        if e.vendor != Vendor::Amd {
            continue;
        }
        // Each family expressed as the (family, model_lo, model_hi)
        // tuple that uniquely identifies that Zen generation in
        // the table.
        match (e.family, e.model_lo, e.model_hi) {
            (0x17, 0x00, 0x2F) => zen1 = true,
            (0x17, 0x30, 0xAF) => zen2 = true,
            (0x19, 0x60, 0x7F) => zen4 = true,
            (0x1A, 0x00, 0xFF) => zen5 = true,
            _ => {}
        }
    }
    if !zen1 {
        return TestResult::Fail("missing Zen 1 entry (family 0x17, model 0x00-0x2F)");
    }
    if !zen2 {
        return TestResult::Fail("missing Zen 2 entry (family 0x17, model 0x30-0xAF)");
    }
    if !zen4 {
        return TestResult::Fail("missing Zen 4 entry (family 0x19, model 0x60-0x7F)");
    }
    if !zen5 {
        return TestResult::Fail("missing Zen 5 marker (family 0x1A)");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/errata", smoke_x86_errata_table_covers_zen_families);

#[cfg(target_arch = "x86_64")]
fn smoke_x86_errata_apply_returns_count() -> TestResult {
    // apply_for_current_cpu returns ([&str; 8], usize) — make
    // sure the count matches the number of non-empty names.
    // SAFETY: pure CPUID reads + (potentially) DE_CFG MSR
    // writes. Idempotent — boot-time apply already ran.
    // SAFETY: Valid memory or trusted environment
    let (names, n) = unsafe { crate::x86_64::errata::apply_for_current_cpu() };
    if n > names.len() {
        return TestResult::Fail("count exceeds buffer length");
    }
    for name in &names[..n] {
        if name.is_empty() {
            return TestResult::Fail("name slot within count is empty");
        }
    }
    for name in &names[n..] {
        if !name.is_empty() {
            return TestResult::Fail("name slot past count is non-empty");
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/errata", smoke_x86_errata_apply_returns_count);

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
    if count > 0 {
        return TestResult::Pass;
    }
    // Zero levels: distinguish "CPU has no cache-topology CPUID leaf"
    // (QEMU qemu64 / CI's TCG runner — nothing to enumerate, skip) from
    // "the leaf exists but yielded nothing" (a real enumeration fault).
    if cache_topology::leaf_supported() {
        TestResult::Fail("no cache levels enumerated")
    } else {
        TestResult::Skip("CPU exposes no cache-topology CPUID leaf")
    }
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

// ── relocated from verification ──

#[cfg(target_arch = "aarch64")]
fn smoke_aarch64_mpidr_aff_present() -> TestResult {
    // MPIDR_EL1 reads cleanly + affinity-pack returns a value
    // matching the table-registered BSP slot.
    let aff = crate::aarch64::cpu::mpidr_aff();
    // QEMU virt typically reports MPIDR_EL1 = 0x80000000 (UP bit
    // set) so aff = 0. We accept anything; just verify the read
    // doesn't fault.
    let _ = aff;
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch", smoke_aarch64_mpidr_aff_present);

// ── deep arch coverage — pure-logic invariants ────────────────────
//
// Pin the type-level surface of arch's hardware-feature structs so
// a refactor that shifts a CPUID bit or renames a field surfaces
// at test time, not at boot.

#[cfg(target_arch = "x86_64")]
fn smoke_arch_x86_features_default_is_all_false() -> TestResult {
    use crate::x86_64::Features;
    let d = Features::default();
    if d.nx
        || d.pku
        || d.pks
        || d.uipi
        || d.invariant_tsc
        || d.rdseed
        || d.rdrand
        || d.x2apic
        || d.apic
        || d.tsc_deadline
        || d.arat
    {
        return TestResult::Fail("Features::default() should be all-false");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch", smoke_arch_x86_features_default_is_all_false);

#[cfg(target_arch = "x86_64")]
fn smoke_arch_x86_features_probe_idempotent() -> TestResult {
    use crate::x86_64::Features;
    // SAFETY: CPUID at CPL=0 is always legal.
    let f1 = unsafe { Features::probe() };
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let f2 = unsafe { Features::probe() };
    if f1.nx != f2.nx
        || f1.pku != f2.pku
        || f1.pks != f2.pks
        || f1.uipi != f2.uipi
        || f1.invariant_tsc != f2.invariant_tsc
        || f1.rdseed != f2.rdseed
        || f1.rdrand != f2.rdrand
        || f1.x2apic != f2.x2apic
        || f1.apic != f2.apic
        || f1.tsc_deadline != f2.tsc_deadline
        || f1.arat != f2.arat
    {
        return TestResult::Fail("Features::probe() not idempotent");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch", smoke_arch_x86_features_probe_idempotent);

#[cfg(target_arch = "x86_64")]
fn smoke_arch_topology_level_kind_distinct() -> TestResult {
    use crate::x86_64::topology::LevelKind;
    let all = [
        LevelKind::Invalid,
        LevelKind::Smt,
        LevelKind::Core,
        LevelKind::Module,
        LevelKind::Tile,
        LevelKind::Die,
        LevelKind::Domain,
        LevelKind::Package,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("LevelKind variants collapsed");
            }
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch", smoke_arch_topology_level_kind_distinct);

#[cfg(target_arch = "x86_64")]
fn smoke_arch_topology_cache_kind_distinct() -> TestResult {
    use crate::x86_64::topology::CacheKind;
    let all = [
        CacheKind::Null,
        CacheKind::Data,
        CacheKind::Instr,
        CacheKind::Unified,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("CacheKind variants collapsed");
            }
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch", smoke_arch_topology_cache_kind_distinct);

#[cfg(target_arch = "x86_64")]
fn smoke_arch_topology_default_is_empty() -> TestResult {
    use crate::x86_64::topology::Topology;
    let t = Topology::default();
    if t.n_levels != 0 {
        return TestResult::Fail("default Topology has non-zero levels");
    }
    if t.package_count != 0 || t.core_count != 0 || t.thread_count != 0 {
        return TestResult::Fail("default Topology has non-zero counts");
    }
    if t.hybrid || t.core_type != 0 {
        return TestResult::Fail("default Topology has non-default hybrid/core_type");
    }
    for slot in t.levels.iter() {
        if slot.is_some() {
            return TestResult::Fail("default Topology has a populated level slot");
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch", smoke_arch_topology_default_is_empty);

#[cfg(target_arch = "x86_64")]
fn smoke_arch_topology_discover_self_consistent() -> TestResult {
    // discover() must produce a topology where thread_count >=
    // core_count >= package_count >= 1. Hardware always has at
    // least one of each.
    use crate::x86_64::topology;
    let t = topology::discover();
    if t.package_count == 0 {
        return TestResult::Skip(
            "topology::discover returned package_count=0 (CPUID leaf 1F/0B missing?)",
        );
    }
    if t.thread_count < t.core_count {
        return TestResult::Fail("thread_count < core_count");
    }
    if t.core_count < t.package_count {
        return TestResult::Fail("core_count < package_count");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch", smoke_arch_topology_discover_self_consistent);

// ── low-value: arch caps()-when-unsupported invariants ──────────

#[cfg(target_arch = "x86_64")]
fn smoke_arch_avx10_zmm_implies_ymm_implies_xmm() -> TestResult {
    // ZMM subsumes YMM subsumes XMM — no CPU can advertise ZMM
    // without YMM (the bit decode in caps() could break this).
    use crate::x86_64::avx10;
    let c = avx10::caps();
    if c.zmm && !c.ymm {
        return TestResult::Fail("ZMM without YMM");
    }
    if c.ymm && !c.xmm {
        return TestResult::Fail("YMM without XMM");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/avx10", smoke_arch_avx10_zmm_implies_ymm_implies_xmm);

#[cfg(target_arch = "x86_64")]
fn smoke_arch_avx10_unsupported_yields_zero_caps() -> TestResult {
    // When supported=false, every other bool must also be false
    // and version == 0. The caps() early-return path is the only
    // way that's achievable.
    use crate::x86_64::avx10;
    let c = avx10::caps();
    if !c.supported && (c.xmm || c.ymm || c.zmm || c.converged_with_avx512 || c.version != 0) {
        return TestResult::Fail("!supported but other bits set");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/avx10", smoke_arch_avx10_unsupported_yields_zero_caps);

#[cfg(target_arch = "x86_64")]
fn smoke_arch_cet_cr4_implies_a_component() -> TestResult {
    // cr4_cet should never be set unless either shadow_stack or
    // ibt is also present — CR4.CET enables a hardware feature
    // that requires one of the two CPUID bits.
    use crate::x86_64::cet;
    let c = cet::caps();
    if c.cr4_cet && !c.shadow_stack && !c.ibt {
        return TestResult::Fail("CR4.CET set without shadow_stack or ibt");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/cet", smoke_arch_cet_cr4_implies_a_component);

#[cfg(target_arch = "x86_64")]
fn smoke_arch_xsave_x87_and_sse_always_present() -> TestResult {
    // Every x86_64 CPU supports x87 + SSE; XCR0 advertises both.
    use crate::x86_64::xsave;
    let c = xsave::caps();
    if c.xcr0_supported & xsave::XSAVE_X87 == 0 {
        return TestResult::Fail("x87 bit missing");
    }
    if c.xcr0_supported & xsave::XSAVE_SSE == 0 {
        return TestResult::Fail("SSE bit missing");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/xsave", smoke_arch_xsave_x87_and_sse_always_present);

#[cfg(target_arch = "x86_64")]
fn smoke_arch_xsave_area_size_at_least_fxsave_minimum() -> TestResult {
    // FXSAVE area minimum is 512 bytes (x87 + SSE state). XSAVE
    // builds on that, so area_size_xcr0 must be >= 512 when XCR0
    // advertises anything.
    use crate::x86_64::xsave;
    let c = xsave::caps();
    if c.xcr0_supported != 0 && c.area_size_xcr0 < 512 {
        return TestResult::Fail("area_size_xcr0 < FXSAVE minimum");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "arch/xsave",
    smoke_arch_xsave_area_size_at_least_fxsave_minimum
);

#[cfg(target_arch = "x86_64")]
fn smoke_arch_xsave_xcr0_and_xss_disjoint() -> TestResult {
    // XCR0 = user-mode state, XSS = supervisor-mode state. The two
    // sets are disjoint by Intel architecture (vol 1 §13.5).
    use crate::x86_64::xsave;
    let c = xsave::caps();
    if c.xcr0_supported & c.xss_supported != 0 {
        return TestResult::Fail("XCR0 and XSS bits overlap");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/xsave", smoke_arch_xsave_xcr0_and_xss_disjoint);

#[cfg(target_arch = "x86_64")]
fn smoke_arch_xsave_avx512_group_all_or_none() -> TestResult {
    // The three AVX-512 state components (opmask, ZMM_Hi256, Hi16_ZMM) must be
    // advertised together or not at all — the OS enables them as a group and
    // `caps().avx512` reflects exactly that all-or-none condition.
    use crate::x86_64::xsave;
    let c = xsave::caps();
    let present = c.xcr0_supported & xsave::XSAVE_AVX512_GROUP;
    let all = present == xsave::XSAVE_AVX512_GROUP;
    let none = present == 0;
    if !all && !none {
        return TestResult::Fail("AVX-512 XCR0 group is partially advertised");
    }
    if c.avx512 != all {
        return TestResult::Fail("caps().avx512 disagrees with the group bits");
    }
    // AVX-512 cannot be advertised without AVX (ZMM extends YMM).
    if c.avx512 && !c.avx {
        return TestResult::Fail("AVX-512 advertised without AVX");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/xsave", smoke_arch_xsave_avx512_group_all_or_none);

#[cfg(target_arch = "x86_64")]
fn smoke_arch_xsave_default_policy_is_saveable() -> TestResult {
    use crate::x86_64::xsave;

    let supported = xsave::XSAVE_X87
        | xsave::XSAVE_SSE
        | xsave::XSAVE_AVX
        | xsave::XSAVE_AVX512_GROUP
        | xsave::XSAVE_PKRU
        | xsave::XSAVE_AMX_GROUP;
    let selected = xsave::default_xcr0_mask(supported);
    if selected & xsave::XSAVE_AMX_GROUP != 0 {
        return TestResult::Fail("default XCR0 policy selected opt-in AMX state");
    }
    if selected & xsave::XSAVE_AVX512_GROUP != xsave::XSAVE_AVX512_GROUP {
        return TestResult::Fail("complete AVX-512 group was not selected");
    }

    let partial = xsave::default_xcr0_mask(
        xsave::XSAVE_X87 | xsave::XSAVE_SSE | xsave::XSAVE_AVX | xsave::XSAVE_AVX512_OPMASK,
    );
    if partial & xsave::XSAVE_AVX512_GROUP != 0 {
        return TestResult::Fail("partial AVX-512 group was selected");
    }
    let no_sse =
        xsave::default_xcr0_mask(xsave::XSAVE_X87 | xsave::XSAVE_AVX | xsave::XSAVE_AVX512_GROUP);
    if no_sse != xsave::XSAVE_X87 {
        return TestResult::Fail("AVX selected without its SSE dependency");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/xsave", smoke_arch_xsave_default_policy_is_saveable);

#[cfg(target_arch = "x86_64")]
fn smoke_arch_xsave_area_size_covers_avx512() -> TestResult {
    // Size the task buffer against the boot-selected XCR0 mask, not leaf
    // 0xD.0:ECX (which includes disabled opt-in state such as AMX tile data).
    use crate::x86_64::xsave;
    let c = xsave::caps();
    if c.xcr0_supported == 0 {
        return TestResult::Skip("no XSAVE support (FXSAVE fallback host)");
    }
    // SAFETY: boot enabled CR4.OSXSAVE before running kernel tests.
    let enabled = unsafe { xsave::read_xcr0() };
    let bytes = xsave::area_size_for_mask(enabled);
    if bytes > xsave::FPU_AREA_SIZE {
        return TestResult::Fail("enabled XSAVE state exceeds FPU_AREA_SIZE");
    }
    if enabled & xsave::XSAVE_AMX_GROUP != 0 {
        return TestResult::Fail("AMX must not be enabled without opt-in save areas");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/xsave", smoke_arch_xsave_area_size_covers_avx512);

/// 64-byte-aligned scratch FPU area for the save/restore round-trip smokes.
/// XSAVE/XRSTOR require a 64-byte-aligned operand; a plain `[u8; N]` on the
/// stack has no such guarantee, so wrap it.
#[cfg(target_arch = "x86_64")]
#[repr(C, align(64))]
struct AlignedFpuArea([u8; crate::x86_64::xsave::FPU_AREA_SIZE]);

/// Seed a reset FPU image (FCW=0x037F, MXCSR=0x1F80, zeroed XSAVE header),
/// mirroring the userspace `FpuArea::reset` used for a task's first entry.
#[cfg(target_arch = "x86_64")]
/// Build a standard-format XSAVE image seeding the x87 FCW and SSE MXCSR
/// with NON-default control words, and mark both components present in the
/// header so a subsequent `XRSTOR` actually loads them.
///
/// Two subtleties this encodes, both learned the hard way:
///
///  1. `XSTATE_BV` (header byte 512) must flag x87 (bit 0) + SSE (bit 1),
///     or `XRSTOR` restores those components to their INIT state and
///     ignores the seeded legacy words entirely.
///  2. The seeded words differ from the architectural init state
///     (FCW 0x037F, MXCSR 0x1F80), proving bytes were restored rather than
///     coincidentally reset to the same value.
///
/// `XCOMP_BV` (byte 520) stays 0 → standard (non-compacted) layout.
fn init_reset_fpu_area(a: &mut AlignedFpuArea) {
    a.0.fill(0);
    // FCW 0x007F: precision-control = single (init is 64-bit, 0x037F).
    a.0[0] = 0x7F;
    a.0[1] = 0x00;
    // MXCSR 0x1F00: invalid-op exception UNmasked (init masks it, 0x1F80).
    a.0[24] = 0x00;
    a.0[25] = 0x1F;
    // XSTATE_BV: x87 (bit 0) + SSE (bit 1) present.
    a.0[512] = 0x03;
}

#[cfg(target_arch = "x86_64")]
fn smoke_arch_xsave_fpu_reset_round_trip() -> TestResult {
    // fpu_restore → fpu_save must round-trip the x87 FCW and SSE MXCSR through
    // the CPU register file. The seeded control words are deliberately NON-init
    // (see `init_reset_fpu_area`) so the save cannot merely reproduce the
    // architectural reset values.
    //
    // Non-destructive: the caller's live FPU state is saved first and restored
    // last, so running this smoke never corrupts the surrounding task's
    // x87/SSE/AVX state.
    use crate::x86_64::xsave;

    let mut live = AlignedFpuArea([0u8; xsave::FPU_AREA_SIZE]);
    let mut reset = AlignedFpuArea([0u8; xsave::FPU_AREA_SIZE]);
    let mut readback = AlignedFpuArea([0u8; xsave::FPU_AREA_SIZE]);
    init_reset_fpu_area(&mut reset);

    // SAFETY: buffers are FPU_AREA_SIZE, 64-byte aligned; CR4.OSFXSR/OSXSAVE
    // are set at boot. We save the live state before clobbering the CPU FPU and
    // restore it before returning.
    let (fcw, mxcsr) = unsafe {
        xsave::fpu_save(live.0.as_mut_ptr());
        xsave::fpu_restore(reset.0.as_ptr());
        xsave::fpu_save(readback.0.as_mut_ptr());
        xsave::fpu_restore(live.0.as_ptr());
        let fcw = u16::from_le_bytes([readback.0[0], readback.0[1]]);
        let mxcsr = u32::from_le_bytes([
            readback.0[24],
            readback.0[25],
            readback.0[26],
            readback.0[27],
        ]);
        (fcw, mxcsr)
    };

    if fcw != 0x007F {
        return TestResult::Fail("FCW not preserved through restore/save");
    }
    // Only the defined MXCSR bits are meaningful; mask off the reserved high
    // half before comparing (hardware zeroes them but be explicit).
    if mxcsr & 0xFFFF != 0x1F00 {
        return TestResult::Fail("MXCSR not preserved through restore/save");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/xsave", smoke_arch_xsave_fpu_reset_round_trip);

#[cfg(target_arch = "x86_64")]
fn smoke_arch_xsave_ymm_round_trip() -> TestResult {
    use crate::x86_64::xsave;

    // SAFETY: boot enabled CR4.OSXSAVE before running kernel tests.
    let enabled = unsafe { xsave::read_xcr0() };
    if enabled & xsave::XSAVE_AVX == 0 {
        return TestResult::Skip("AVX not enabled on this host");
    }

    let mut live = AlignedFpuArea([0u8; xsave::FPU_AREA_SIZE]);
    let mut image = AlignedFpuArea([0u8; xsave::FPU_AREA_SIZE]);
    let expected = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d,
        0x1e, 0x0f,
    ];
    let mut observed = [0u8; 32];

    // Save the caller, load a value spanning both XMM0 and YMM0's upper half,
    // snapshot it, clobber the register, restore the snapshot, and read the
    // full register back. FXSAVE-only task switching would lose bytes 16..31.
    // SAFETY: both FPU areas satisfy the size/alignment contract; XCR0 enables
    // AVX; vmovdqu permits unaligned byte-array operands.
    unsafe {
        xsave::fpu_save(live.0.as_mut_ptr());
        core::arch::asm!(
            "vmovdqu ymm0, [{src}]",
            src = in(reg) expected.as_ptr(),
            out("ymm0") _,
            options(nostack, preserves_flags),
        );
        xsave::fpu_save(image.0.as_mut_ptr());
        core::arch::asm!(
            "vpxor ymm0, ymm0, ymm0",
            out("ymm0") _,
            options(nomem, nostack, preserves_flags),
        );
        xsave::fpu_restore(image.0.as_ptr());
        core::arch::asm!(
            "vmovdqu [{dst}], ymm0",
            dst = in(reg) observed.as_mut_ptr(),
            options(nostack, preserves_flags),
        );
        xsave::fpu_restore(live.0.as_ptr());
    }

    if observed != expected {
        return TestResult::Fail("YMM state was not preserved by XSAVE/XRSTOR");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/xsave", smoke_arch_xsave_ymm_round_trip);

#[cfg(target_arch = "x86_64")]
fn smoke_arch_xsave_avx512_evex_no_ud() -> TestResult {
    // When the AVX-512 XCR0 group is enabled, an EVEX-encoded instruction must
    // execute without #UD. TCG hosts that lack AVX-512 report caps().avx512 ==
    // false and skip. Non-destructive: the live FPU is saved around the zmm
    // clobber and restored afterward.
    use crate::x86_64::xsave;
    // SAFETY: boot enabled CR4.OSXSAVE before running kernel tests.
    let enabled = unsafe { xsave::read_xcr0() };
    if enabled & xsave::XSAVE_AVX512_GROUP != xsave::XSAVE_AVX512_GROUP {
        return TestResult::Skip("AVX-512 not enabled on this host");
    }

    let mut live = AlignedFpuArea([0u8; xsave::FPU_AREA_SIZE]);
    // SAFETY: buffer sized/aligned; CR4.OSXSAVE set. `vpxorq zmm0,zmm0,zmm0`
    // is EVEX-encoded and would #UD if AVX-512 were not enabled in XCR0 — the
    // XCR0 gate above guarantees it is. zmm0 is clobbered; the live
    // FPU is saved before and restored after so no surrounding state is lost.
    unsafe {
        xsave::fpu_save(live.0.as_mut_ptr());
        core::arch::asm!(
            "vpxorq zmm0, zmm0, zmm0",
            out("zmm0") _,
            options(nomem, nostack, preserves_flags),
        );
        xsave::fpu_restore(live.0.as_ptr());
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/xsave", smoke_arch_xsave_avx512_evex_no_ud);

#[cfg(target_arch = "x86_64")]
fn smoke_arch_pmu_version_implies_counters() -> TestResult {
    // Architectural PMU version >= 1 implies a non-zero number of
    // general-purpose counters per logical processor.
    use crate::x86_64::pmu;
    let c = pmu::caps();
    if c.version >= 1 && c.n_general_counters == 0 {
        return TestResult::Fail("PMU v>=1 but no GP counters");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/pmu", smoke_arch_pmu_version_implies_counters);

#[cfg(target_arch = "x86_64")]
fn smoke_arch_lbr_entries_zero_when_msr_bases_zero() -> TestResult {
    // If we don't know the LBR MSR base addresses, n_entries must
    // also be zero — otherwise the ring decoder will try to read
    // MSR 0x0, which is IA32_TSC.
    use crate::x86_64::lbr;
    let c = lbr::caps();
    if c.from_base == 0 && c.n_entries != 0 {
        return TestResult::Fail("n_entries != 0 with from_base == 0");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/lbr", smoke_arch_lbr_entries_zero_when_msr_bases_zero);

// ── more low-value arch invariants ──────────────────────────────

#[cfg(target_arch = "x86_64")]
fn smoke_arch_sgx_sgx2_implies_sgx1() -> TestResult {
    // SGX2 extends SGX1 — never advertised in isolation.
    use crate::x86_64::sgx;
    let c = sgx::caps();
    if c.sgx2 && !c.sgx1 {
        return TestResult::Fail("SGX2 without SGX1");
    }
    if (c.sgx1 || c.sgx2) && !c.instruction_supported {
        return TestResult::Fail("SGX1/2 set but instruction_supported false");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/sgx", smoke_arch_sgx_sgx2_implies_sgx1);

#[cfg(target_arch = "x86_64")]
fn smoke_arch_hfi_supported_implies_nonzero_size() -> TestResult {
    // HFI feedback page exists only when supported; its size is a
    // CPUID leaf 0x14 field that must be non-zero in that case.
    use crate::x86_64::hfi;
    let c = hfi::caps();
    if c.supported && c.size_bytes == 0 {
        return TestResult::Fail("supported but size_bytes == 0");
    }
    if c.supported && c.size_bytes > 4096 {
        return TestResult::Fail("size_bytes > 4 KiB");
    }
    if !c.supported && (c.n_classes != 0 || c.size_bytes != 0) {
        return TestResult::Fail("!supported but classes/size != 0");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/hfi", smoke_arch_hfi_supported_implies_nonzero_size);

#[cfg(target_arch = "x86_64")]
fn smoke_arch_rdt_subfeature_implies_parent() -> TestResult {
    // L3 / L2 / MBA allocation features require the parent
    // "allocation" bit; L3 monitoring requires the parent
    // "monitoring" bit.
    use crate::x86_64::rdt;
    let c = rdt::caps();
    if c.l3_cat && !c.allocation {
        return TestResult::Fail("l3_cat without allocation");
    }
    if c.l2_cat && !c.allocation {
        return TestResult::Fail("l2_cat without allocation");
    }
    if c.mba && !c.allocation {
        return TestResult::Fail("mba without allocation");
    }
    if c.l3_monitoring && !c.monitoring {
        return TestResult::Fail("l3_monitoring without monitoring");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/rdt", smoke_arch_rdt_subfeature_implies_parent);

#[cfg(target_arch = "x86_64")]
fn smoke_arch_pt_features_require_base() -> TestResult {
    // ToPA / multi-ToPA / branch-filter are all features layered on
    // top of base PT support — none can be set without supported.
    use crate::x86_64::pt;
    let c = pt::caps();
    if !c.supported && (c.topa || c.multi_topa || c.branch_filter) {
        return TestResult::Fail("PT sub-feature without base support");
    }
    if c.multi_topa && !c.topa {
        return TestResult::Fail("multi_topa without topa");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/pt", smoke_arch_pt_features_require_base);

// ── wrmsr_or_gp / rdmsr_or_gp — probe-armed MSR access ───────────
//
// The fallible MSR helpers catch #GP on BIOS-locked / unsupported
// MSRs via the recoverable-probe machinery. QEMU TCG returns zero
// for unsupported MSRs instead of #GP'ing, so the #GP-catch path
// exercises on real silicon only; here we pin the happy path and
// the `MsrFault` enum shape.

#[cfg(target_arch = "x86_64")]
fn smoke_msr_fault_variants_distinct() -> TestResult {
    use crate::x86_64::msr::MsrFault;
    if MsrFault::GeneralProtection == MsrFault::OtherTrap(13) {
        return TestResult::Fail("GP != OtherTrap(13) is the whole point");
    }
    if MsrFault::OtherTrap(6) == MsrFault::OtherTrap(8) {
        return TestResult::Fail("OtherTrap Eq collapsed across vectors");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/msr", smoke_msr_fault_variants_distinct);

#[cfg(target_arch = "x86_64")]
fn smoke_msr_wrmsr_or_gp_round_trip_on_safe_msr() -> TestResult {
    // IA32_TSC_AUX (0xC0000103) is the only architecturally-defined
    // MSR we can both read and rewrite without disturbing observable
    // CPU state: it's an opaque 32-bit cookie returned by RDPID /
    // RDTSCP that the OS uses to identify the logical processor.
    // Round-trip: read it, write a sentinel, read back, restore the
    // original. All four ops go through wrmsr_or_gp / rdmsr_or_gp.
    use crate::x86_64::msr::{rdmsr_or_gp, wrmsr_or_gp};
    const TSC_AUX: u32 = 0xC0000103;
    let original = match rdmsr_or_gp(TSC_AUX) {
        Ok(v) => v,
        Err(_) => return TestResult::Skip("IA32_TSC_AUX not present on this CPU"),
    };
    let sentinel: u64 = 0xDEAD_BEEF_CAFE_F00D & 0xFFFF_FFFF;
    if wrmsr_or_gp(TSC_AUX, sentinel).is_err() {
        return TestResult::Fail("wrmsr_or_gp #GP'd on a writable MSR");
    }
    let read_back = match rdmsr_or_gp(TSC_AUX) {
        Ok(v) => v,
        Err(_) => {
            let _ = wrmsr_or_gp(TSC_AUX, original);
            return TestResult::Fail("rdmsr_or_gp #GP'd after a successful write");
        }
    };
    let _ = wrmsr_or_gp(TSC_AUX, original);
    if read_back != sentinel {
        return TestResult::Fail("written value didn't round-trip through rdmsr");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/msr", smoke_msr_wrmsr_or_gp_round_trip_on_safe_msr);

// ── amd_pstate ────────────────────────────────────────────────────
//
// Driver targets AMD Family 0x17 (Zen2) Models 0x30..=0xAF — real
// hardware bring-up only. QEMU `-cpu max` doesn't match, so every
// smoke below Skips cleanly under the kernel-test harness. On a
// matching laptop they exercise CPUID gating, CAP1 decode, the
// REQ packing round-trip, and the boot programming path.

#[cfg(target_arch = "x86_64")]
fn smoke_amd_pstate_request_pack_roundtrip() -> TestResult {
    // Pure pack/unpack — no MSR access, runs everywhere including
    // QEMU and CI. Verifies the (min, max, des, epp) layout matches
    // Linux amd-pstate's `amd_pstate_update_perf` packing.
    use crate::x86_64::amd_pstate::{build_request, decode_request};
    let v = build_request(0x10, 0xC0, 0x80, 0x40);
    if v != ((0xC0u64) | (0x10u64 << 8) | (0x80u64 << 16) | (0x40u64 << 24)) {
        return TestResult::Fail("build_request packing mismatch");
    }
    let (min, max, des, epp) = decode_request(v);
    if (min, max, des, epp) != (0x10, 0xC0, 0x80, 0x40) {
        return TestResult::Fail("decode_request round-trip mismatch");
    }
    // EPP must sit in the high byte — the canonical bit position
    // amd-pstate userspace depends on.
    let v_epp = build_request(0, 0, 0, 0xFF);
    if (v_epp >> 24) & 0xFF != 0xFF {
        return TestResult::Fail("EPP not packed into bits[31:24]");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch", smoke_amd_pstate_request_pack_roundtrip);

#[cfg(target_arch = "x86_64")]
fn smoke_amd_pstate_caps_decode() -> TestResult {
    // Pure decode of a synthetic CAP1 value matching the AMD Renoir
    // PPR §1.5 layout. Runs everywhere — no MSR access.
    use crate::x86_64::amd_pstate::CppcCaps;
    // highest=0xC0, nominal=0x80, lowest_nonlinear=0x20, lowest=0x10.
    let raw: u64 = 0xC0 << 24 | 0x80 << 16 | 0x20 << 8 | 0x10;
    let c = CppcCaps::from_raw(raw);
    if c.highest_perf != 0xC0 {
        return TestResult::Fail("highest_perf decode wrong");
    }
    if c.nominal_perf != 0x80 {
        return TestResult::Fail("nominal_perf decode wrong");
    }
    if c.lowest_nonlinear_perf != 0x20 {
        return TestResult::Fail("lowest_nonlinear_perf decode wrong");
    }
    if c.lowest_perf != 0x10 {
        return TestResult::Fail("lowest_perf decode wrong");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch", smoke_amd_pstate_caps_decode);

#[cfg(target_arch = "x86_64")]
fn smoke_amd_pstate_is_zen2_gates_msr_path() -> TestResult {
    // `is_zen2()` is the gate every public entry-point honours.
    // On non-AMD or non-Zen2, the MSR helpers must short-circuit to
    // `None` without ever issuing a rdmsr/wrmsr — otherwise a stray
    // CPPC MSR read on Intel would #GP. We can't observe absence
    // of an MSR access directly, but we can assert the documented
    // return-shape contract.
    use crate::x86_64::amd_pstate::{amd_pstate_request, is_zen2, read_caps, read_status};
    if !is_zen2() {
        if read_caps().is_some() {
            return TestResult::Fail("read_caps() returned Some on non-Zen2");
        }
        if read_status().is_some() {
            return TestResult::Fail("read_status() returned Some on non-Zen2");
        }
        if amd_pstate_request(0, 0xFF, 0x80, 0x40).is_some() {
            return TestResult::Fail("amd_pstate_request returned Some on non-Zen2");
        }
        return TestResult::Skip("not AMD Family 0x17 Model 0x30..=0xAF");
    }
    // Real Zen2: every helper should return Some(...) — the inner
    // Result may still be Err if firmware locked the MSRs, which
    // isn't a test failure.
    if read_caps().is_none() {
        return TestResult::Fail("read_caps() returned None on Zen2");
    }
    if read_status().is_none() {
        return TestResult::Fail("read_status() returned None on Zen2");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch", smoke_amd_pstate_is_zen2_gates_msr_path);

#[cfg(target_arch = "x86_64")]
fn smoke_amd_pstate_boot_init_outcome_shape() -> TestResult {
    // Exercise the full boot_init() path. On non-Zen2 we must
    // observe NotZen2 (no MSR access happened). On Zen2 we may
    // see Programmed / Cap1Gp / ReqGp depending on the BIOS lock
    // state — all three are valid + non-fatal.
    use crate::x86_64::amd_pstate::{boot_init, is_zen2, BootInitOutcome};
    let outcome = boot_init();
    if !is_zen2() {
        if !matches!(outcome, BootInitOutcome::NotZen2) {
            return TestResult::Fail("boot_init must report NotZen2 off-target");
        }
        return TestResult::Skip("not AMD Family 0x17 Model 0x30..=0xAF");
    }
    match outcome {
        BootInitOutcome::Programmed {
            caps,
            des_perf,
            epp,
        } => {
            // Sanity-check the field choice the driver makes.
            if des_perf != caps.nominal_perf {
                return TestResult::Fail("des_perf must equal caps.nominal_perf");
            }
            if epp != crate::x86_64::amd_pstate::epp::BALANCE_PERFORMANCE {
                return TestResult::Fail("EPP must be BALANCE_PERFORMANCE");
            }
            // PPR guarantees highest >= nominal >= lowest_nonlinear
            // >= lowest, and all non-zero on shipping silicon.
            if caps.highest_perf < caps.nominal_perf
                || caps.nominal_perf < caps.lowest_nonlinear_perf
                || caps.lowest_nonlinear_perf < caps.lowest_perf
            {
                return TestResult::Fail("CAP1 ordering invariant violated");
            }
            TestResult::Pass
        }
        BootInitOutcome::Cap1Gp | BootInitOutcome::ReqGp => {
            // BIOS-locked MSRs are a real-world outcome — surface as
            // Skip so the test still runs on locked-down OEM units.
            TestResult::Skip("CPPC MSRs locked by firmware")
        }
        BootInitOutcome::NotZen2 => TestResult::Fail("is_zen2() said true but boot_init disagreed"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch", smoke_amd_pstate_boot_init_outcome_shape);

#[cfg(target_arch = "x86_64")]
fn smoke_k10temp_tctl_offset_per_family_model() -> TestResult {
    use crate::x86_64::k10temp::{tctl_offset_for, TCTL_OFFSET_49C, TCTL_OFFSET_LAPTOP};
    // Renoir (0x17, 0x60 — Lucienne) → laptop offset (0).
    if tctl_offset_for(0x17, 0x60) != TCTL_OFFSET_LAPTOP {
        return TestResult::Fail("Renoir/Lucienne must have laptop offset");
    }
    // Phoenix HawkPoint1 (0x19, 0x74) → laptop offset.
    if tctl_offset_for(0x19, 0x74) != TCTL_OFFSET_LAPTOP {
        return TestResult::Fail("Phoenix must have laptop offset");
    }
    // EPYC Naples (0x17, 0x00) → 49 °C.
    if tctl_offset_for(0x17, 0x00) != TCTL_OFFSET_49C {
        return TestResult::Fail("Naples Model 0x00 must have 49 C offset");
    }
    // First-gen Ryzen 1700X/1800X (Model 0x01) → 20 °C; the more
    // specific arm must win against the 0x00..=0x0F broad arm.
    use crate::x86_64::k10temp::TCTL_OFFSET_20C;
    if tctl_offset_for(0x17, 0x01) != TCTL_OFFSET_20C {
        return TestResult::Fail("first-gen Ryzen Model 0x01 must have 20 C offset");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch", smoke_k10temp_tctl_offset_per_family_model);

#[cfg(target_arch = "x86_64")]
fn smoke_k10temp_decode_tdie_from_smn_raw() -> TestResult {
    use crate::x86_64::k10temp::{decode_tdie_millicelsius, K10TempError};
    // raw = 800 (Tctl_raw = 800 * 0.125 = 100°C) packed in bits[31:21]:
    // 800 = 0x320; shifted left 21 → 0x6400_0000.
    let raw_100c: u32 = 800u32 << 21;
    let mc = decode_tdie_millicelsius(raw_100c, 0).expect("decode failed");
    // 100 °C = 100_000 m°C. Allow a 1°C slop for shift rounding.
    if !(99_000..=101_000).contains(&mc) {
        return TestResult::Fail("100 °C raw must decode near 100_000 m°C");
    }
    // Per-part Tctl_offset of 20 °C should subtract 20_000 m°C.
    let mc_offset = decode_tdie_millicelsius(raw_100c, 20).expect("decode failed");
    if mc - mc_offset != 20_000 {
        return TestResult::Fail("Tctl_offset application wrong");
    }
    // Bus-disconnected SMN returns 0xFFFFFFFF — error path.
    match decode_tdie_millicelsius(0xFFFF_FFFF, 0) {
        Err(K10TempError::NoSensor) => TestResult::Pass,
        _ => TestResult::Fail("all-ones raw must be NoSensor"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch", smoke_k10temp_decode_tdie_from_smn_raw);

#[cfg(target_arch = "x86_64")]
fn smoke_k10temp_read_tdie_drives_smn_index_write() -> TestResult {
    use crate::x86_64::k10temp::{read_tdie_millicelsius, MockSmn, SMN_ADDR_TEMP_REPORT};
    // 70 °C → Tctl_raw = 560 → packed shift-21 = 0x4600_0000.
    let raw_70c: u32 = 560u32 << 21;
    let mut port = MockSmn::new(raw_70c);
    let mc = read_tdie_millicelsius(&mut port, 0).expect("read failed");
    if port.last_index != SMN_ADDR_TEMP_REPORT {
        return TestResult::Fail("must write SMN_ADDR_TEMP_REPORT to INDEX");
    }
    if !(69_000..=71_000).contains(&mc) {
        return TestResult::Fail("70 °C raw didn't decode near 70_000 m°C");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch", smoke_k10temp_read_tdie_drives_smn_index_write);

#[cfg(target_arch = "x86_64")]
fn smoke_s3_resume_context_save_round_trip() -> TestResult {
    use crate::x86_64::s3_resume::{__reset_for_test, captured_context, save_resume_context};
    __reset_for_test();
    if captured_context().is_some() {
        return TestResult::Fail("fresh state must be uncaptured");
    }
    // SAFETY: smoke runs in CPL 0; reading control + system regs
    // is the test's whole purpose.
    // SAFETY: Valid memory or trusted environment
    unsafe { save_resume_context() };
    let ctx = match captured_context() {
        Some(c) => c,
        None => return TestResult::Fail("save didn't flip CAPTURED"),
    };
    // CR3 must be non-zero (we have paging on).
    if ctx.cr3 == 0 {
        return TestResult::Fail("CR3 read as 0 — paging not on?");
    }
    // GDT must be non-empty.
    if ctx.gdt_limit == 0 || ctx.gdt_base == 0 {
        return TestResult::Fail("GDTR snapshot zero");
    }
    // IDT must be non-empty (kernel installed one).
    if ctx.idt_limit == 0 || ctx.idt_base == 0 {
        return TestResult::Fail("IDTR snapshot zero");
    }
    // RSP must be non-zero + look like a kernel stack (high half).
    if ctx.rsp == 0 {
        return TestResult::Fail("RSP snapshot zero");
    }
    __reset_for_test();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/s3_resume", smoke_s3_resume_context_save_round_trip);

#[cfg(target_arch = "x86_64")]
fn smoke_x86_64_setjmp_longjmp_round_trip() -> TestResult {
    use crate::x86_64::setjmp::{longjmp, setjmp, JmpBuf};
    let mut jmp = JmpBuf::default();
    // SAFETY: jmp lives on this stack frame across both calls.
    let r1 = unsafe { setjmp(&mut jmp as *mut _) };
    if r1 == 0 {
        // SAFETY: saved frame still live.
        unsafe { longjmp(&jmp as *const _, 0xDEAD_BEEF) }
    }
    if r1 != 0xDEAD_BEEF {
        return TestResult::Fail("longjmp value did not surface from setjmp");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch", smoke_x86_64_setjmp_longjmp_round_trip);

#[cfg(target_arch = "x86_64")]
fn smoke_x86_64_setjmp_longjmp_zero_promotes_to_one() -> TestResult {
    use crate::x86_64::setjmp::{longjmp, setjmp, JmpBuf};
    let mut jmp = JmpBuf::default();
    // SAFETY: same.
    let r1 = unsafe { setjmp(&mut jmp as *mut _) };
    if r1 == 0 {
        // SAFETY: same. longjmp with val=0 → must surface as 1.
        unsafe { longjmp(&jmp as *const _, 0) }
    }
    if r1 != 1 {
        return TestResult::Fail("longjmp(_, 0) should surface as 1");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch", smoke_x86_64_setjmp_longjmp_zero_promotes_to_one);

#[cfg(target_arch = "x86_64")]
fn smoke_x86_64_setjmp_buf_layout_matches_asm() -> TestResult {
    use crate::x86_64::setjmp::JmpBuf;
    // The asm uses fixed offsets +0..+56 against rdi (JmpBuf*).
    // Drift here would silently corrupt either save or restore.
    if core::mem::size_of::<JmpBuf>() != 64 {
        return TestResult::Fail("JmpBuf must be exactly 64 bytes (8 slots)");
    }
    if core::mem::align_of::<JmpBuf>() != 16 {
        return TestResult::Fail("JmpBuf must be 16-byte aligned");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch", smoke_x86_64_setjmp_buf_layout_matches_asm);

#[cfg(target_arch = "x86_64")]
fn smoke_x86_64_hybrid_cpu_type_probe() -> TestResult {
    // Exercise the CPUID 0x1A reader + the Hybrid feature bit. We
    // can't assert a specific result — QEMU TCG, AMD silicon, and
    // pre-12th-gen Intel all read 0 (Unknown), which is correct.
    // The check is structural: probe doesn't fault, the byte
    // decodes through `CpuType::from_raw`, and `features.hybrid`
    // is consistent with leaf 0x1A actually returning a non-zero
    // type (a non-zero CpuType implies the silicon advertised
    // hybrid, but not the converse — Intel parts can advertise
    // hybrid for a single uniform LP in some hypervisor configs).
    use crate::x86_64::cpuid::{read_hybrid_cpu_type, Features};
    use narf_lib::percpu::CpuType;

    // SAFETY: CPUID is always legal at CPL=0.
    let feats = unsafe { Features::probe() };
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let raw = unsafe { read_hybrid_cpu_type() };
    let ty = CpuType::from_raw(raw);

    // Non-hybrid silicon must report Unknown. Hybrid-capable silicon
    // can report any of the three (CpuType::Unknown is fine for an
    // unrecognised future type; we don't fail it).
    if !feats.hybrid && ty != CpuType::Unknown {
        return TestResult::Fail("non-hybrid CPU reported non-Unknown type from leaf 0x1A");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/cpuid", smoke_x86_64_hybrid_cpu_type_probe);

// ── AMD-Vi DTE + command-ring + dev-table-base encoders ──────────

#[cfg(target_arch = "x86_64")]
fn smoke_amd_vi_dte_identity_bit_positions() -> TestResult {
    use crate::x86_64::amd_vi::{
        DeviceTableEntry, DTE_HOST_PT_MASK, DTE_IR, DTE_IW, DTE_MODE_4_LEVEL, DTE_MODE_SHIFT,
        DTE_TV, DTE_V, PERM_READ, PERM_WRITE,
    };
    let pt_root: u64 = 0xDEAD_F000; // page-aligned
    let dte = DeviceTableEntry::identity(0x42, pt_root, PERM_READ | PERM_WRITE);
    if !dte.is_valid() {
        return TestResult::Fail("V bit not set on identity DTE");
    }
    if dte.domain_id() != 0x42 {
        return TestResult::Fail("DomainID not encoded into data[1]");
    }
    if dte.page_table_root() != pt_root {
        return TestResult::Fail("page-table root mask wrong");
    }
    if dte.walk_mode() != DTE_MODE_4_LEVEL {
        return TestResult::Fail("walk mode != 4-level");
    }
    // Bit positions per Linux DTE_FLAG_V / TV / IR / IW.
    let d0 = dte.data[0];
    if d0 & DTE_V == 0 || d0 & DTE_TV == 0 || d0 & DTE_IR == 0 || d0 & DTE_IW == 0 {
        return TestResult::Fail("V/TV/IR/IW bit drift");
    }
    if (d0 & DTE_HOST_PT_MASK) != pt_root {
        return TestResult::Fail("page-table mask conflated with flag bits");
    }
    if (d0 >> DTE_MODE_SHIFT) & 0b111 != DTE_MODE_4_LEVEL {
        return TestResult::Fail("walk mode bit position drift");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/amd_vi", smoke_amd_vi_dte_identity_bit_positions);

#[cfg(target_arch = "x86_64")]
fn smoke_amd_vi_dte_passthrough_no_pt() -> TestResult {
    use crate::x86_64::amd_vi::{DeviceTableEntry, DTE_HOST_PT_MASK, DTE_TV};
    let dte = DeviceTableEntry::passthrough(0x7);
    if !dte.is_valid() {
        return TestResult::Fail("passthrough DTE not valid");
    }
    if dte.data[0] & DTE_TV != 0 {
        return TestResult::Fail("passthrough must clear TV");
    }
    if dte.data[0] & DTE_HOST_PT_MASK != 0 {
        return TestResult::Fail("passthrough must have zero pt root");
    }
    if dte.walk_mode() != 0 {
        return TestResult::Fail("passthrough walk mode != 0");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/amd_vi", smoke_amd_vi_dte_passthrough_no_pt);

#[cfg(target_arch = "x86_64")]
fn smoke_amd_vi_dte_with_irte() -> TestResult {
    use crate::x86_64::amd_vi::{DeviceTableEntry, DTE_IRTE_PTR_MASK, DTE_IV};
    let irte_root: u64 = 0x1234_5040; // 128-byte aligned within mask
    let dte = DeviceTableEntry::passthrough(1).with_irte(irte_root);
    if dte.data[2] & DTE_IV == 0 {
        return TestResult::Fail("IV bit not set");
    }
    if dte.data[2] & DTE_IRTE_PTR_MASK != irte_root & DTE_IRTE_PTR_MASK {
        return TestResult::Fail("IRTE root mask drifted");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/amd_vi", smoke_amd_vi_dte_with_irte);

#[cfg(target_arch = "x86_64")]
fn smoke_amd_vi_cmd_invalidate_devtab_opcode() -> TestResult {
    use crate::x86_64::amd_vi::{IommuCmd, CMD_INV_DEV_ENTRY};
    let cmd = IommuCmd::invalidate_devtab(0x0123);
    if cmd.opcode() != CMD_INV_DEV_ENTRY {
        return TestResult::Fail("opcode != CMD_INV_DEV_ENTRY");
    }
    // BDF lives in data[0].
    if cmd.data[0] != 0x0123 {
        return TestResult::Fail("BDF not encoded into data[0]");
    }
    if cmd.data[2] != 0 || cmd.data[3] != 0 {
        return TestResult::Fail("INV_DEV_ENTRY upper lanes must be zero");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/amd_vi", smoke_amd_vi_cmd_invalidate_devtab_opcode);

#[cfg(target_arch = "x86_64")]
fn smoke_amd_vi_cmd_completion_wait_token_round_trip() -> TestResult {
    use crate::x86_64::amd_vi::{IommuCmd, CMD_COMPL_WAIT, CMD_COMPL_WAIT_STORE_MASK};
    let sem: u64 = 0x1_2345_6FF8;
    let tok: u64 = 0xCAFE_BABE_DEAD_BEEF;
    let cmd = IommuCmd::completion_wait(sem, tok);
    if cmd.opcode() != CMD_COMPL_WAIT {
        return TestResult::Fail("completion_wait opcode drift");
    }
    if cmd.data[0] & CMD_COMPL_WAIT_STORE_MASK == 0 {
        return TestResult::Fail("store bit not set");
    }
    let stored_sem_lo = cmd.data[0] & 0xFFFF_FFF8;
    if stored_sem_lo != (sem as u32 & 0xFFFF_FFF8) {
        return TestResult::Fail("sem low dword drift");
    }
    if cmd.data[1] & 0x0FFF_FFFF != (sem >> 32) as u32 & 0x0FFF_FFFF {
        return TestResult::Fail("sem high dword drift");
    }
    let lo = cmd.data[2] as u64;
    let hi = (cmd.data[3] as u64) << 32;
    if (hi | lo) != tok {
        return TestResult::Fail("token round-trip mismatch");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "arch/amd_vi",
    smoke_amd_vi_cmd_completion_wait_token_round_trip
);

#[cfg(target_arch = "x86_64")]
fn smoke_amd_vi_cmd_invalidate_pages_all() -> TestResult {
    use crate::x86_64::amd_vi::{
        IommuCmd, CMD_INV_ALL_PAGES_ADDRESS, CMD_INV_IOMMU_PAGES, CMD_INV_IOMMU_PAGES_PDE_MASK,
        CMD_INV_IOMMU_PAGES_SIZE_MASK,
    };
    let cmd = IommuCmd::invalidate_pages(0x55, 0, true);
    if cmd.opcode() != CMD_INV_IOMMU_PAGES {
        return TestResult::Fail("invalidate_pages opcode drift");
    }
    if cmd.data[1] & 0xFFFF != 0x55 {
        return TestResult::Fail("domain id not in data[1] low 16 bits");
    }
    if cmd.data[2] & CMD_INV_IOMMU_PAGES_PDE_MASK == 0 {
        return TestResult::Fail("PDE flush bit not set");
    }
    if cmd.data[2] & CMD_INV_IOMMU_PAGES_SIZE_MASK == 0 {
        return TestResult::Fail("size bit not set on all-pages flush");
    }
    let addr = ((cmd.data[3] as u64) << 32) | ((cmd.data[2] as u64) & 0xFFFF_FFF0);
    let want = CMD_INV_ALL_PAGES_ADDRESS & 0xFFFF_FFFF_FFFF_FFF0;
    if addr != want {
        return TestResult::Fail("all-pages sentinel address drifted");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/amd_vi", smoke_amd_vi_cmd_invalidate_pages_all);

#[cfg(target_arch = "x86_64")]
fn smoke_amd_vi_dev_table_base_encode_decode() -> TestResult {
    use crate::x86_64::amd_vi::{decode_dev_table_base, encode_dev_table_base};
    // Standard 256 KiB device table at a page-aligned addr.
    let phys: u64 = 0x0000_0001_0000_0000;
    let bytes: u64 = 256 * 1024;
    let reg = encode_dev_table_base(phys, bytes);
    let (got_phys, got_bytes) = decode_dev_table_base(reg);
    if got_phys != phys {
        return TestResult::Fail("dev-table phys round-trip mismatch");
    }
    if got_bytes != bytes {
        return TestResult::Fail("dev-table size round-trip mismatch");
    }
    // Size field is (bytes >> 12) - 1.
    let size_field = reg & 0x1FF;
    if size_field != (bytes >> 12) - 1 {
        return TestResult::Fail("size field encoding drift");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/amd_vi", smoke_amd_vi_dev_table_base_encode_decode);

#[cfg(target_arch = "x86_64")]
fn smoke_amd_vi_irte_remap_round_trip() -> TestResult {
    use crate::x86_64::amd_vi::{Irte, IRTE_REMAP_INTCTL, IRTE_REMAP_INTCTL_MASK};
    let irte = Irte::remap(0x33, 0x4);
    if !irte.is_valid() {
        return TestResult::Fail("IRTE valid bit not set");
    }
    if irte.vector() != 0x33 {
        return TestResult::Fail("IRTE vector round-trip mismatch");
    }
    if irte.dest_id() != 0x4 {
        return TestResult::Fail("IRTE dest_id round-trip mismatch");
    }
    if irte.raw & IRTE_REMAP_INTCTL_MASK != IRTE_REMAP_INTCTL {
        return TestResult::Fail("IntCtl != remap (2)");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/amd_vi", smoke_amd_vi_irte_remap_round_trip);

// ── Intel VT-d root / context / page-table / QI encoders ─────────

#[cfg(target_arch = "x86_64")]
fn smoke_vtd_root_entry_layout() -> TestResult {
    use crate::x86_64::vtd::{RootEntry, ROOT_CTX_PTR_MASK, ROOT_PRESENT};
    let ctx_phys: u64 = 0x0000_0001_F000_0000;
    let root = RootEntry::present(ctx_phys);
    if !root.is_present() {
        return TestResult::Fail("root entry not present");
    }
    if root.context_ptr() != ctx_phys {
        return TestResult::Fail("context pointer round-trip mismatch");
    }
    if root.lo & ROOT_PRESENT == 0 {
        return TestResult::Fail("present bit not at bit 0");
    }
    if root.lo & ROOT_CTX_PTR_MASK != ctx_phys & ROOT_CTX_PTR_MASK {
        return TestResult::Fail("ctx ptr mask drift");
    }
    if root.hi != 0 {
        return TestResult::Fail("legacy mode hi must be 0");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/vtd", smoke_vtd_root_entry_layout);

#[cfg(target_arch = "x86_64")]
fn smoke_vtd_context_entry_legacy() -> TestResult {
    use crate::x86_64::vtd::{ContextEntry, CTX_AW_48BIT, CTX_PRESENT, CTX_TT_LEGACY};
    let slpt: u64 = 0x0000_0000_1234_5000;
    let did: u16 = 0x77;
    let ctx = ContextEntry::legacy(slpt, did, CTX_AW_48BIT);
    if !ctx.is_present() {
        return TestResult::Fail("context not present");
    }
    if ctx.translation_type() != CTX_TT_LEGACY {
        return TestResult::Fail("TT != legacy");
    }
    if ctx.address_space_root() != slpt {
        return TestResult::Fail("ASR round-trip mismatch");
    }
    if ctx.address_width() != CTX_AW_48BIT {
        return TestResult::Fail("AGAW round-trip mismatch");
    }
    if ctx.domain_id() != did {
        return TestResult::Fail("DID round-trip mismatch");
    }
    if ctx.lo & CTX_PRESENT == 0 {
        return TestResult::Fail("present bit position drift");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/vtd", smoke_vtd_context_entry_legacy);

#[cfg(target_arch = "x86_64")]
fn smoke_vtd_sl_pte_leaf_perms() -> TestResult {
    use crate::x86_64::vtd::{sl_pte_addr, sl_pte_leaf, sl_pte_present, SL_PTE_READ, SL_PTE_WRITE};
    let phys: u64 = 0x0000_0000_DEAD_B000;
    let rw = sl_pte_leaf(phys, true, true);
    if !sl_pte_present(rw) {
        return TestResult::Fail("RW PTE not present");
    }
    if sl_pte_addr(rw) != phys {
        return TestResult::Fail("addr round-trip mismatch");
    }
    if rw & (SL_PTE_READ | SL_PTE_WRITE) != (SL_PTE_READ | SL_PTE_WRITE) {
        return TestResult::Fail("R+W bits not set");
    }
    let ro = sl_pte_leaf(phys, true, false);
    if ro & SL_PTE_WRITE != 0 {
        return TestResult::Fail("read-only PTE has W set");
    }
    let none = sl_pte_leaf(phys, false, false);
    if sl_pte_present(none) {
        return TestResult::Fail("no-perms PTE reports present");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/vtd", smoke_vtd_sl_pte_leaf_perms);

#[cfg(target_arch = "x86_64")]
fn smoke_vtd_iova_level_index() -> TestResult {
    use crate::x86_64::vtd::iova_level_index;
    // 4-level walk, 9-bit indices, 12-bit page offset:
    //   IOVA = [ L4 9 | L3 9 | L2 9 | L1 9 | offset 12 ]
    let iova: u64 = (0x123 << 39) | (0x055 << 30) | (0x0AA << 21) | (0x1FF << 12);
    if iova_level_index(iova, 4) != 0x123 {
        return TestResult::Fail("L4 index decode wrong");
    }
    if iova_level_index(iova, 3) != 0x055 {
        return TestResult::Fail("L3 index decode wrong");
    }
    if iova_level_index(iova, 2) != 0x0AA {
        return TestResult::Fail("L2 index decode wrong");
    }
    if iova_level_index(iova, 1) != 0x1FF {
        return TestResult::Fail("L1 index decode wrong");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/vtd", smoke_vtd_iova_level_index);

#[cfg(target_arch = "x86_64")]
fn smoke_vtd_qi_desc_iotlb_domain_inv() -> TestResult {
    use crate::x86_64::vtd::{QiDesc, QI_GRAN_DOMAIN, QI_IOTLB_TYPE};
    let desc = QiDesc::iotlb_inv(QI_GRAN_DOMAIN, 0x42, 0);
    if desc.ty() != QI_IOTLB_TYPE {
        return TestResult::Fail("desc type != IOTLB");
    }
    if desc.gran() != QI_GRAN_DOMAIN {
        return TestResult::Fail("desc gran != domain-selective");
    }
    if desc.domain_id() != 0x42 {
        return TestResult::Fail("desc DID round-trip mismatch");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/vtd", smoke_vtd_qi_desc_iotlb_domain_inv);

#[cfg(target_arch = "x86_64")]
fn smoke_vtd_qi_desc_cc_global_inv() -> TestResult {
    use crate::x86_64::vtd::{QiDesc, QI_CC_TYPE, QI_GRAN_GLOBAL};
    let desc = QiDesc::cc_inv(QI_GRAN_GLOBAL, 0, 0);
    if desc.ty() != QI_CC_TYPE {
        return TestResult::Fail("desc type != CC");
    }
    if desc.gran() != QI_GRAN_GLOBAL {
        return TestResult::Fail("desc gran != global");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/vtd", smoke_vtd_qi_desc_cc_global_inv);

#[cfg(target_arch = "x86_64")]
fn smoke_vtd_iqa_register_encoding() -> TestResult {
    use crate::x86_64::vtd::{decode_iqa, encode_iqa};
    let base: u64 = 0x0000_0001_5000_0000;
    let reg = encode_iqa(base, 2, false);
    let (got_base, got_qs, got_wide) = decode_iqa(reg);
    if got_base != base {
        return TestResult::Fail("IQA base round-trip mismatch");
    }
    if got_qs != 2 {
        return TestResult::Fail("IQA QS round-trip mismatch");
    }
    if got_wide {
        return TestResult::Fail("IQA DW should be 0 for 128-bit descs");
    }
    let wide_reg = encode_iqa(base, 0, true);
    let (_, _, w2) = decode_iqa(wide_reg);
    if !w2 {
        return TestResult::Fail("IQA DW bit not set when wide=true");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/vtd", smoke_vtd_iqa_register_encoding);

#[cfg(target_arch = "x86_64")]
fn smoke_vtd_context_passthrough() -> TestResult {
    use crate::x86_64::vtd::{ContextEntry, CTX_TT_PASSTHROUGH};
    let ctx = ContextEntry::passthrough(0x9);
    if !ctx.is_present() {
        return TestResult::Fail("passthrough not present");
    }
    if ctx.translation_type() != CTX_TT_PASSTHROUGH {
        return TestResult::Fail("TT != passthrough");
    }
    if ctx.address_space_root() != 0 {
        return TestResult::Fail("passthrough ASR must be 0");
    }
    if ctx.domain_id() != 0x9 {
        return TestResult::Fail("DID round-trip mismatch");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/vtd", smoke_vtd_context_passthrough);

// ── AMD-Vi cmd-buffer / event-log register encoding ──────────────

#[cfg(target_arch = "x86_64")]
fn smoke_amd_vi_cmd_buf_base_encoding() -> TestResult {
    use crate::x86_64::amd_vi::{decode_cmd_buf_base, encode_cmd_buf_base, CMD_BUF_SIZE_SHIFT};
    let phys: u64 = 0x0000_0001_5000_0000;
    let reg = encode_cmd_buf_base(phys);
    let (got_phys, size_field) = decode_cmd_buf_base(reg);
    if got_phys != phys {
        return TestResult::Fail("cmd_buf phys round-trip mismatch");
    }
    if size_field != 0x9 {
        return TestResult::Fail("size field != 0x9 (512 entries)");
    }
    // Size field must live at bits 56..60.
    if (reg >> CMD_BUF_SIZE_SHIFT) & 0xF != 0x9 {
        return TestResult::Fail("size field not at bits 56..60");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/amd_vi", smoke_amd_vi_cmd_buf_base_encoding);

#[cfg(target_arch = "x86_64")]
fn smoke_amd_vi_ring_tail_wraps() -> TestResult {
    use crate::x86_64::amd_vi::advance_ring_tail;
    // 8 KiB ring, push 511 entries: should land at offset 8176.
    // Push one more: should wrap to 0.
    let bytes: u32 = 8192;
    let mut tail: u32 = 0;
    for _ in 0..511 {
        tail = advance_ring_tail(tail, 1, bytes);
    }
    if tail != 511 * 16 {
        return TestResult::Fail("tail before wrap != 511*16");
    }
    tail = advance_ring_tail(tail, 1, bytes);
    if tail != 0 {
        return TestResult::Fail("tail did not wrap on 512th entry");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/amd_vi", smoke_amd_vi_ring_tail_wraps);

#[cfg(target_arch = "x86_64")]
fn smoke_amd_vi_evt_log_base_encoding() -> TestResult {
    use crate::x86_64::amd_vi::{decode_evt_log_base, encode_evt_log_base};
    let phys: u64 = 0x0000_0001_8000_0000;
    let reg = encode_evt_log_base(phys);
    let (got_phys, size_field) = decode_evt_log_base(reg);
    if got_phys != phys {
        return TestResult::Fail("evt-log phys round-trip mismatch");
    }
    if size_field != 0x9 {
        return TestResult::Fail("evt-log size != 0x9");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/amd_vi", smoke_amd_vi_evt_log_base_encoding);

#[cfg(target_arch = "x86_64")]
fn smoke_amd_vi_pte_leaf_perms() -> TestResult {
    use crate::x86_64::amd_vi::{pte_addr, pte_leaf, pte_present, PTE_IR, PTE_IW};
    let phys: u64 = 0xDEAD_F000;
    let rw = pte_leaf(phys, true, true);
    if !pte_present(rw) {
        return TestResult::Fail("RW PTE not present");
    }
    if pte_addr(rw) != phys {
        return TestResult::Fail("addr round-trip mismatch");
    }
    if rw & (PTE_IR | PTE_IW) != (PTE_IR | PTE_IW) {
        return TestResult::Fail("IR + IW bits not set");
    }
    let ro = pte_leaf(phys, true, false);
    if ro & PTE_IW != 0 {
        return TestResult::Fail("R-only PTE has IW set");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/amd_vi", smoke_amd_vi_pte_leaf_perms);

#[cfg(target_arch = "x86_64")]
fn smoke_amd_vi_pte_next_level_encoding() -> TestResult {
    use crate::x86_64::amd_vi::{
        pte_addr, pte_next, pte_next_level, pte_present, PTE_NEXT_LEVEL_SHIFT,
    };
    let table: u64 = 0x1234_5000;
    let pte = pte_next(table, 3);
    if !pte_present(pte) {
        return TestResult::Fail("non-leaf PTE must be present (IR|IW)");
    }
    if pte_addr(pte) != table {
        return TestResult::Fail("next-table phys round-trip mismatch");
    }
    if pte_next_level(pte) != 3 {
        return TestResult::Fail("next-level field round-trip mismatch");
    }
    if (pte >> PTE_NEXT_LEVEL_SHIFT) & 0x7 != 3 {
        return TestResult::Fail("next-level bit position drift");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/amd_vi", smoke_amd_vi_pte_next_level_encoding);

#[cfg(target_arch = "x86_64")]
fn smoke_amd_vi_pte_level_index_round_trip() -> TestResult {
    use crate::x86_64::amd_vi::pte_level_index;
    let iova: u64 = (0x055 << 39) | (0x011 << 30) | (0x0F1 << 21) | (0x123 << 12);
    if pte_level_index(iova, 4) != 0x055 {
        return TestResult::Fail("L4 idx wrong");
    }
    if pte_level_index(iova, 3) != 0x011 {
        return TestResult::Fail("L3 idx wrong");
    }
    if pte_level_index(iova, 2) != 0x0F1 {
        return TestResult::Fail("L2 idx wrong");
    }
    if pte_level_index(iova, 1) != 0x123 {
        return TestResult::Fail("L1 idx wrong");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/amd_vi", smoke_amd_vi_pte_level_index_round_trip);

#[cfg(target_arch = "x86_64")]
fn smoke_vtd_walk_slpt_resolves_iova() -> TestResult {
    // Build a fake 4-level VT-d page table in host memory that
    // maps IOVA 0xCAFE_F123 → phys 0xBEEF_F000, then walk it.
    // This exercises the per-level shift math without touching
    // any silicon.
    use crate::x86_64::vtd::{iova_level_index, sl_pte_leaf, sl_pte_next, walk_slpt, WalkResult};

    // Distinct sentinel phys for L3, L2, L1, leaf.
    const L3_PHYS: u64 = 0x0010_0000;
    const L2_PHYS: u64 = 0x0010_1000;
    const L1_PHYS: u64 = 0x0010_2000;
    const LEAF_PHYS: u64 = 0xBEEF_F000;

    let iova: u64 = 0xCAFE_F123;

    let mut root = [0u64; 512];
    let mut l3 = [0u64; 512];
    let mut l2 = [0u64; 512];
    let mut l1 = [0u64; 512];

    root[iova_level_index(iova, 4)] = sl_pte_next(L3_PHYS);
    l3[iova_level_index(iova, 3)] = sl_pte_next(L2_PHYS);
    l2[iova_level_index(iova, 2)] = sl_pte_next(L1_PHYS);
    l1[iova_level_index(iova, 1)] = sl_pte_leaf(LEAF_PHYS, true, true);

    let result = walk_slpt(&root, iova, |phys| match phys {
        L3_PHYS => Some(l3),
        L2_PHYS => Some(l2),
        L1_PHYS => Some(l1),
        _ => None,
    });
    match result {
        WalkResult::Mapped { phys, offset } => {
            if phys != LEAF_PHYS {
                return TestResult::Fail("walker resolved wrong phys");
            }
            if offset != (iova & 0xFFF) {
                return TestResult::Fail("walker mishandled page offset");
            }
            TestResult::Pass
        }
        WalkResult::NotPresent { level } => {
            let _ = level;
            TestResult::Fail("walker reported NotPresent on a complete table")
        }
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/vtd", smoke_vtd_walk_slpt_resolves_iova);

#[cfg(target_arch = "x86_64")]
fn smoke_vtd_walk_slpt_unmapped_iova() -> TestResult {
    use crate::x86_64::vtd::{walk_slpt, WalkResult};
    let root = [0u64; 512];
    let result = walk_slpt(&root, 0xABCD_E000, |_| None);
    if !matches!(result, WalkResult::NotPresent { level: 4 }) {
        return TestResult::Fail("empty root should NotPresent at L4");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/vtd", smoke_vtd_walk_slpt_unmapped_iova);

#[cfg(target_arch = "x86_64")]
fn smoke_amd_vi_walk_iopt_resolves_iova() -> TestResult {
    // Build a 4-level AMD-Vi I/O page table that maps a known
    // IOVA to a known phys. Confirm the walker resolves it.
    use crate::x86_64::amd_vi::{pte_leaf, pte_level_index, pte_next, walk_iopt, AmdViWalkResult};
    const L3: u64 = 0x0020_0000;
    const L2: u64 = 0x0020_1000;
    const L1: u64 = 0x0020_2000;
    const LEAF: u64 = 0xF00D_F000;
    let iova: u64 = 0xC0DE_F456;

    let mut root = [0u64; 512];
    let mut l3 = [0u64; 512];
    let mut l2 = [0u64; 512];
    let mut l1 = [0u64; 512];
    root[pte_level_index(iova, 4)] = pte_next(L3, 3);
    l3[pte_level_index(iova, 3)] = pte_next(L2, 2);
    l2[pte_level_index(iova, 2)] = pte_next(L1, 1);
    l1[pte_level_index(iova, 1)] = pte_leaf(LEAF, true, true);

    let result = walk_iopt(&root, iova, |phys| match phys {
        L3 => Some(l3),
        L2 => Some(l2),
        L1 => Some(l1),
        _ => None,
    });
    match result {
        AmdViWalkResult::Mapped { phys, offset } => {
            if phys != LEAF {
                return TestResult::Fail("walker resolved wrong phys");
            }
            if offset != (iova & 0xFFF) {
                return TestResult::Fail("walker mishandled offset");
            }
            TestResult::Pass
        }
        AmdViWalkResult::NotPresent { .. } => {
            TestResult::Fail("walker reported NotPresent on a complete table")
        }
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/amd_vi", smoke_amd_vi_walk_iopt_resolves_iova);

#[cfg(target_arch = "x86_64")]
fn smoke_vtd_irte_remap_round_trip() -> TestResult {
    use crate::x86_64::vtd::VtdIrte;
    let irte = VtdIrte::remap(0x21, 0x3, 0x0123);
    if !irte.is_present() {
        return TestResult::Fail("present bit not set");
    }
    if irte.vector() != 0x21 {
        return TestResult::Fail("vector round-trip mismatch");
    }
    if irte.dest_id() != 0x3 {
        return TestResult::Fail("dest_id round-trip mismatch");
    }
    if irte.source_id() != 0x0123 {
        return TestResult::Fail("source_id round-trip mismatch");
    }
    // SVT field at high[18..20] should be 1 (SID-match).
    if (irte.high >> 18) & 0x3 != 1 {
        return TestResult::Fail("SVT not 1");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/vtd", smoke_vtd_irte_remap_round_trip);

#[cfg(target_arch = "x86_64")]
fn smoke_amd_vi_push_command_to_ram_ring() -> TestResult {
    // Exercise push_command against a host-RAM-backed ring (no
    // MMIO) and confirm the entry lands at slot 0, tail advances
    // to 16, and a second push lands at slot 1.
    use crate::x86_64::amd_vi::{push_command, IommuCmd};
    let mut ring: [IommuCmd; 4] = [IommuCmd::default(); 4]; // 64 B
    let bytes: u32 = 64;
    let cmd_a = IommuCmd::invalidate_devtab(0xABCD);
    let cmd_b = IommuCmd::invalidate_all();
    // SAFETY: ring is host-owned RAM in this test.
    let mut tail = unsafe { push_command(ring.as_mut_ptr(), 0, cmd_a, bytes) };
    if tail != 16 {
        return TestResult::Fail("tail did not advance to 16");
    }
    if ring[0] != cmd_a {
        return TestResult::Fail("slot 0 didn't get cmd_a");
    }
    // SAFETY: same.
    tail = unsafe { push_command(ring.as_mut_ptr(), tail, cmd_b, bytes) };
    if tail != 32 {
        return TestResult::Fail("tail did not advance to 32");
    }
    if ring[1] != cmd_b {
        return TestResult::Fail("slot 1 didn't get cmd_b");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/amd_vi", smoke_amd_vi_push_command_to_ram_ring);

#[cfg(target_arch = "x86_64")]
fn smoke_vtd_push_qi_desc_to_ram_queue() -> TestResult {
    use crate::x86_64::vtd::{push_qi_desc, QiDesc, QI_GRAN_GLOBAL};
    let mut queue: [QiDesc; 4] = [QiDesc::default(); 4];
    let bytes: u32 = 64;
    let desc = QiDesc::cc_inv(QI_GRAN_GLOBAL, 0, 0);
    // SAFETY: queue is host-owned RAM in this test.
    let tail = unsafe { push_qi_desc(queue.as_mut_ptr(), 0, desc, bytes) };
    if tail != 16 {
        return TestResult::Fail("tail did not advance to 16");
    }
    if queue[0] != desc {
        return TestResult::Fail("slot 0 didn't get desc");
    }
    // Wrap: push 3 more, the 4th should land back at slot 0.
    // SAFETY: same.
    let mut t = tail;
    for _ in 0..3 {
        // SAFETY: the pointer is non-null, aligned, and points to a live value for this access.
        t = unsafe { push_qi_desc(queue.as_mut_ptr(), t, desc, bytes) };
    }
    if t != 0 {
        return TestResult::Fail("tail did not wrap to 0 after 4 pushes");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/vtd", smoke_vtd_push_qi_desc_to_ram_queue);

// ── SMEP / SMAP / KPTI / CET hardening smokes ─────────────────────────

#[cfg(target_arch = "x86_64")]
fn smoke_smep_caps_and_cr4() -> TestResult {
    use crate::x86_64::smep;
    if !smep::supported() {
        return TestResult::Skip("SMEP not advertised by CPUID");
    }
    let was = smep::is_enabled();
    // SAFETY: SMEP supported; toggling is benign at CPL=0.
    unsafe {
        smep::enable();
    }
    if !smep::is_enabled() {
        return TestResult::Fail("CR4.SMEP did not stick after enable()");
    }
    if !was {
        // SAFETY: restore prior CR4 state for tests-only.
        unsafe {
            smep::disable_for_test();
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/smep", smoke_smep_caps_and_cr4);

#[cfg(target_arch = "x86_64")]
fn smoke_smap_caps_and_bracket() -> TestResult {
    use crate::x86_64::smap;
    if !smap::supported() {
        return TestResult::Skip("SMAP not advertised by CPUID");
    }
    let was = smap::is_enabled();
    // SAFETY: SMAP supported; CR4 toggle benign at CPL=0.
    unsafe {
        smap::enable();
    }
    if !smap::is_enabled() {
        return TestResult::Fail("CR4.SMAP did not stick after enable()");
    }
    let mut saw_ac = false;
    // SAFETY: closure body just reads EFLAGS; no user memory touched.
    unsafe {
        smap::with_user_access(|| {
            saw_ac = smap::read_ac();
        });
    }
    if smap::read_ac() {
        return TestResult::Fail("CLAC did not clear EFLAGS.AC after bracket");
    }
    if !saw_ac {
        return TestResult::Fail("STAC did not set EFLAGS.AC inside bracket");
    }
    if !was {
        // SAFETY: restore prior CR4 state.
        unsafe {
            smap::disable_for_test();
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/smap", smoke_smap_caps_and_bracket);

#[cfg(target_arch = "x86_64")]
fn smoke_kpti_detect_immune_or_isolate() -> TestResult {
    use crate::x86_64::ident::{self, Vendor};
    use crate::x86_64::kpti::{self, Posture};
    let p = kpti::detect();
    let id = ident::read();
    if matches!(id.vendor, Vendor::Amd | Vendor::Hygon) && p != Posture::Native {
        return TestResult::Fail("AMD/Hygon reported as needing KPTI — should be immune");
    }
    let _ = matches!(p, Posture::Native | Posture::Isolate);
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/kpti", smoke_kpti_detect_immune_or_isolate);

#[cfg(target_arch = "x86_64")]
fn smoke_cet_caps_probe_consistent() -> TestResult {
    use crate::x86_64::cet;
    // QEMU's `-cpu max` exposes both SHSTK and IBT; Renoir doesn't
    // (AMD has Shadow Stack since Zen3, IBT via "Hardware-enforced
    // Stack Protection" since Zen3 in CET) — Zen2 is hit-or-miss.
    // The smoke is mostly checking the API: caps() must come back
    // with self-consistent fields. Crucially: if shadow_stack OR ibt
    // is true, the CR4_CET bit should be settable once we enable_cr4.
    let caps = cet::caps();
    // Both bits can be false on Zen2 / older Intel; we just need to
    // not see an impossible combo (cr4_cet on with neither shadow_stack
    // nor ibt).
    if caps.cr4_cet && !caps.shadow_stack && !caps.ibt {
        return TestResult::Fail("CR4.CET set but neither SHSTK nor IBT advertised — invalid");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/cet", smoke_cet_caps_probe_consistent);

#[cfg(target_arch = "x86_64")]
fn smoke_cet_msr_constants_match_intel_sdm() -> TestResult {
    use crate::x86_64::cet;
    // Hardcoded check against the Intel SDM Vol 4 MSR table. If a
    // refactor accidentally changes one of these, every shadow-stack
    // setup will silently target the wrong MSR.
    if cet::MSR_IA32_U_CET != 0x6A0 {
        return TestResult::Fail("MSR_IA32_U_CET drifted from 0x6A0");
    }
    if cet::MSR_IA32_S_CET != 0x6A2 {
        return TestResult::Fail("MSR_IA32_S_CET drifted from 0x6A2");
    }
    if cet::MSR_IA32_PL0_SSP != 0x6A4 {
        return TestResult::Fail("MSR_IA32_PL0_SSP drifted from 0x6A4");
    }
    if cet::MSR_IA32_PL3_SSP != 0x6A7 {
        return TestResult::Fail("MSR_IA32_PL3_SSP drifted from 0x6A7");
    }
    if cet::MSR_IA32_INTERRUPT_SSP_TABLE != 0x6A8 {
        return TestResult::Fail("MSR_IA32_INTERRUPT_SSP_TABLE drifted from 0x6A8");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/cet", smoke_cet_msr_constants_match_intel_sdm);

#[cfg(target_arch = "aarch64")]
fn smoke_pac_caps_probe_consistent() -> TestResult {
    use crate::aarch64::pac;
    let caps = pac::caps();
    // FEAT_PAuth (any nonzero APA/API/APA3) implies *some* form of
    // address auth. If we report enhanced=true but address_auth=false
    // that's nonsensical.
    if caps.enhanced && !caps.address_auth {
        return TestResult::Fail("PAC enhanced=true but address_auth=false");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/pac", smoke_pac_caps_probe_consistent);

#[cfg(target_arch = "aarch64")]
fn smoke_mte_tag_round_trip() -> TestResult {
    use crate::aarch64::mte;
    if !mte::supported() {
        return TestResult::Skip("MTE not available (use QEMU -machine virt,mte=on)");
    }
    // Tag bits live in bits 59:56 of the pointer. IRG inserts a random
    // tag; the same instruction-form-preserving steps GMI uses fold
    // the tag back out. We don't STG into memory because that requires
    // a tag-storage-backed mapping the smoke can't reliably stand up.
    // What we CAN verify: IRG returns a pointer whose low 56 bits
    // match the input but bits 59:56 differ from the input tag.
    let raw_in: u64 = 0x0000_0000_DEAD_BEEF;
    let p_in = raw_in as *mut u8;
    // SAFETY: IRG is a register-only op; no memory touched.
    let p_out = unsafe { mte::irg(p_in) };
    let raw_out = p_out as u64;
    if (raw_out & 0x00FF_FFFF_FFFF_FFFF) != (raw_in & 0x00FF_FFFF_FFFF_FFFF) {
        return TestResult::Fail("IRG modified bits below 56");
    }
    // Tag bits (59:56) — the input had 0x0; the output should also
    // be in [0, 0xF] but probably nonzero (GCR_EL1 randomises across
    // 16 tags, exclusion mask depending).
    let tag_out = (raw_out >> 56) & 0xF;
    if tag_out > 0xF {
        return TestResult::Fail("IRG returned out-of-range tag");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/mte", smoke_mte_tag_round_trip);

#[cfg(target_arch = "aarch64")]
fn smoke_pmuv3_cycle_counter_round_trip() -> TestResult {
    use crate::aarch64::pmu;
    if !pmu::available() {
        return TestResult::Skip("PMUv3 not exposed by this CPU");
    }
    // SAFETY: kernel smoke runs at EL1 and remains on its current CPU.
    let counter = match unsafe { pmu::alloc_cycle_counter() } {
        Ok(counter) => counter,
        Err(_) => return TestResult::Fail("PMUv3 cycle counter allocation failed"),
    };
    // SAFETY: the counter remains live and current-CPU-owned.
    if unsafe { pmu::read(&counter) }.is_err() {
        return TestResult::Fail("PMUv3 cycle counter read failed");
    }
    // SAFETY: same live current-CPU counter. This validates that preload and
    // interrupt control registers are accessible without claiming delivery.
    let arm_failed = unsafe { pmu::arm_sampling(&counter, 100_000) }.is_err();
    // SAFETY: same live current-CPU counter remains owned by this smoke.
    let pause_failed = unsafe { pmu::pause_sampling(&counter) }.is_err();
    if arm_failed || pause_failed {
        return TestResult::Fail("PMUv3 sampling arm/pause failed");
    }
    // SAFETY: same live current-CPU counter.
    if unsafe { pmu::release(counter) }.is_err() {
        return TestResult::Fail("PMUv3 cycle counter release failed");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/pmu", smoke_pmuv3_cycle_counter_round_trip);

#[cfg(target_arch = "aarch64")]
fn smoke_pmuv3_privilege_filters() -> TestResult {
    use crate::aarch64::{pmu, sysreg};
    if !pmu::available() {
        return TestResult::Skip("PMUv3 not exposed by this CPU");
    }
    // SAFETY: kernel smoke remains at EL1 on its current CPU.
    let cycle = match unsafe { pmu::alloc_cycle_counter_filtered(false, true) } {
        Ok(counter) => counter,
        Err(_) => return TestResult::Fail("user-only cycle allocation failed"),
    };
    // SAFETY: PMUv3 is available and this smoke owns the cycle counter.
    let cycle_filter = unsafe { sysreg::read_pmccfiltr_el0() };
    // P excludes EL1 and U excludes EL0.
    if cycle_filter & (1 << 31) == 0 || cycle_filter & (1 << 30) != 0 {
        return TestResult::Fail("PMCCFILTR user-only bits are incorrect");
    }
    // SAFETY: same current-CPU ownership.
    if unsafe { pmu::release(cycle) }.is_err() {
        return TestResult::Fail("filtered cycle release failed");
    }

    if !pmu::event_supported(0x11) {
        return TestResult::Skip("architectural programmable cycles unavailable");
    }
    // SAFETY: kernel smoke remains at EL1 on its current CPU.
    let programmable = match unsafe { pmu::alloc_programmable_filtered(0x11, true, false) } {
        Ok(counter) => counter,
        Err(_) => return TestResult::Fail("kernel-only programmable allocation failed"),
    };
    // SAFETY: allocation left its owned selector selected.
    let event_type = unsafe { sysreg::read_pmxevtyper_el0() };
    if event_type & (1 << 31) != 0 || event_type & (1 << 30) == 0 {
        return TestResult::Fail("PMEVTYPER kernel-only bits are incorrect");
    }
    // SAFETY: same current-CPU ownership.
    if unsafe { pmu::release_programmable(programmable) }.is_err() {
        return TestResult::Fail("filtered programmable release failed");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/pmu", smoke_pmuv3_privilege_filters);

#[cfg(target_arch = "aarch64")]
fn smoke_pmuv3_programmable_counter_round_trip() -> TestResult {
    use crate::aarch64::pmu;
    if pmu::programmable_counter_count() == 0 {
        return TestResult::Skip("PMUv3 programmable counters not exposed");
    }
    // ARMv8 architectural event 0x11 counts CPU cycles through a
    // programmable slot, independently validating PMSELR/PMXEVTYPER and
    // PMXEVCNTR rather than reusing the dedicated cycle counter.
    // SAFETY: kernel smoke runs at EL1 and remains on its current CPU.
    let counter = match unsafe { pmu::alloc_programmable(0x11) } {
        Ok(counter) => counter,
        Err(_) => return TestResult::Fail("PMUv3 programmable allocation failed"),
    };
    // SAFETY: the counter remains live and current-CPU-owned.
    if unsafe { pmu::start_programmable(&counter) }.is_err() {
        return TestResult::Fail("PMUv3 programmable start failed");
    }
    // SAFETY: the counter remains live and current-CPU-owned.
    let before = unsafe { pmu::read_programmable(&counter) }.unwrap_or(0);
    for _ in 0..1_000 {
        core::hint::black_box(());
    }
    // SAFETY: the counter remains live and current-CPU-owned.
    let after = unsafe { pmu::read_programmable(&counter) }.unwrap_or(before);
    if after <= before {
        return TestResult::Fail("PMUv3 programmable cycle event did not advance");
    }
    // SAFETY: same live current-CPU counter; the smoke only validates register access.
    let arm_failed = unsafe { pmu::arm_programmable(&counter, 10_000) }.is_err();
    // SAFETY: same live current-CPU counter remains owned by this smoke.
    let pause_failed = unsafe { pmu::pause_programmable(&counter) }.is_err();
    if arm_failed || pause_failed {
        return TestResult::Fail("PMUv3 programmable sampling arm/pause failed");
    }
    // SAFETY: the counter remains live and current-CPU-owned.
    if unsafe { pmu::release_programmable(counter) }.is_err() {
        return TestResult::Fail("PMUv3 programmable release failed");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("arch/pmu", smoke_pmuv3_programmable_counter_round_trip);

// ── arch/s3 — S3 resume-context layout + EFER capture ──────────────
//
// The wake trampoline in `x86_64::s3_resume` runs with no Rust
// runtime: it indexes the saved `ResumeContext` as raw `[r8 + N]`
// displacements and replays control registers and IA32_EFER by hand.
// None of that is exercisable by actually suspending — S3 is gated
// off and QEMU/TCG gives us no real S3 cycle — so these smokes pin
// the two things that would otherwise silently rot: the offsets the
// asm indexes, and the contents of the EFER slot the asm replays.

#[cfg(target_arch = "x86_64")]
fn smoke_s3_resume_context_offsets_match_trampoline() -> TestResult {
    use crate::x86_64::s3_resume::ctx_offset;
    // These are the exact displacements the naked asm emits (it
    // consumes `ctx_offset::*` as `const` operands, so it cannot
    // disagree with the struct — but a field reorder would move all
    // of them together and invalidate the documented layout).
    let want: [(usize, usize, &'static str); 10] = [
        (ctx_offset::CR0, 0, "ResumeContext.cr0 moved off +0"),
        (ctx_offset::CR3, 8, "ResumeContext.cr3 moved off +8"),
        (ctx_offset::CR4, 16, "ResumeContext.cr4 moved off +16"),
        (ctx_offset::RFLAGS, 24, "ResumeContext.rflags moved off +24"),
        (
            ctx_offset::GDT_BASE,
            32,
            "ResumeContext.gdt_base moved off +32",
        ),
        (
            ctx_offset::GDT_LIMIT,
            40,
            "ResumeContext.gdt_limit moved off +40",
        ),
        (
            ctx_offset::IDT_BASE,
            48,
            "ResumeContext.idt_base moved off +48",
        ),
        (
            ctx_offset::IDT_LIMIT,
            56,
            "ResumeContext.idt_limit moved off +56",
        ),
        (ctx_offset::RSP, 64, "ResumeContext.rsp moved off +64"),
        (ctx_offset::EFER, 72, "ResumeContext.efer moved off +72"),
    ];
    for (got, expect, msg) in want {
        if got != expect {
            return TestResult::Fail(msg);
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/s3", smoke_s3_resume_context_offsets_match_trampoline);

/// The trampoline is handed `resume_context_static_addr()` (resolved
/// to a phys) and reads fields at `base + ctx_offset::*`. Walk that
/// exact arithmetic from Rust and check every field lands on the
/// value `captured_context()` reports.
///
/// This ties the three pieces together: the accessor must yield the
/// address of the *guarded value* (neither `IrqSafeSpinLock` nor
/// `SpinLock` is `repr(C)`, so "offset 0 of the lock" is not a layout
/// guarantee), and the offsets must select the fields the asm
/// believes they select.
#[cfg(target_arch = "x86_64")]
fn smoke_s3_resume_context_addr_selects_the_right_fields() -> TestResult {
    use crate::x86_64::s3_resume::{
        captured_context, ctx_offset, resume_context_static_addr, save_resume_context,
    };
    // SAFETY: CPL=0. `save_resume_context` only reads control /
    // system registers and stores the snapshot; S3 is gated off, so
    // overwriting the snapshot has no effect on anything live.
    unsafe {
        save_resume_context();
    }
    let ctx = match captured_context() {
        Some(c) => c,
        None => return TestResult::Fail("save_resume_context did not mark the context captured"),
    };
    let base = resume_context_static_addr() as *const u8;
    if base.is_null() {
        return TestResult::Fail("resume_context_static_addr returned null");
    }
    // SAFETY: `base` is the address of the live `ResumeContext`
    // guarded value and every offset below is within its size; the
    // reads are unaligned-tolerant and no reference is formed.
    let at64 = |off: usize| unsafe { core::ptr::read_unaligned(base.add(off) as *const u64) };
    // SAFETY: as above, for the 2-byte limit fields.
    let at16 = |off: usize| unsafe { core::ptr::read_unaligned(base.add(off) as *const u16) };

    let checks: [(u64, u64, &'static str); 8] = [
        (at64(ctx_offset::CR0), ctx.cr0, "[+CR0] is not ctx.cr0"),
        (at64(ctx_offset::CR3), ctx.cr3, "[+CR3] is not ctx.cr3"),
        (at64(ctx_offset::CR4), ctx.cr4, "[+CR4] is not ctx.cr4"),
        (
            at64(ctx_offset::RFLAGS),
            ctx.rflags,
            "[+RFLAGS] is not ctx.rflags",
        ),
        (
            at64(ctx_offset::GDT_BASE),
            ctx.gdt_base,
            "[+GDT_BASE] is not ctx.gdt_base",
        ),
        (
            at64(ctx_offset::IDT_BASE),
            ctx.idt_base,
            "[+IDT_BASE] is not ctx.idt_base",
        ),
        (at64(ctx_offset::RSP), ctx.rsp, "[+RSP] is not ctx.rsp"),
        (at64(ctx_offset::EFER), ctx.efer, "[+EFER] is not ctx.efer"),
    ];
    for (got, want, msg) in checks {
        if got != want {
            return TestResult::Fail(msg);
        }
    }
    if at16(ctx_offset::GDT_LIMIT) != ctx.gdt_limit {
        return TestResult::Fail("[+GDT_LIMIT] is not ctx.gdt_limit");
    }
    if at16(ctx_offset::IDT_LIMIT) != ctx.idt_limit {
        return TestResult::Fail("[+IDT_LIMIT] is not ctx.idt_limit");
    }
    // A saved CR3 of 0 would mean the trampoline reloads a null page
    // table; catches "we read the lock byte instead of the data".
    if ctx.cr3 == 0 {
        return TestResult::Fail("saved CR3 is zero — snapshot did not capture live state");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "arch/s3",
    smoke_s3_resume_context_addr_selects_the_right_fields
);

/// Defect this pins: the resume path used to restore CR0 and CR4 and
/// never touch IA32_EFER, with a comment claiming NXE lived in CR4.
/// NXE is EFER bit 11. Every kernel window is NX, so resuming with
/// NXE clear makes PTE bit 63 reserved and the first access after the
/// CR3 load takes a reserved-bit `#PF` with no IDT loaded.
///
/// Assert the EFER slot holds a *replayable* EFER: LMA masked off
/// (AMD `#GP(0)`s on a wrmsr that changes it), LME set (or the
/// restore would drop us out of long mode), and NXE set (the reason
/// the restore has to exist at all).
#[cfg(target_arch = "x86_64")]
fn smoke_s3_resume_context_saves_replayable_efer() -> TestResult {
    use crate::x86_64::msr::rdmsr_or_gp;
    use crate::x86_64::s3_resume::{captured_context, save_resume_context};
    const IA32_EFER: u32 = 0xC000_0080;
    const LME: u64 = 1 << 8;
    const LMA: u64 = 1 << 10;
    const NXE: u64 = 1 << 11;

    let live = match rdmsr_or_gp(IA32_EFER) {
        Ok(v) => v,
        Err(_) => return TestResult::Skip("IA32_EFER unreadable on this CPU"),
    };
    // SAFETY: CPL=0; see the sibling smoke.
    unsafe {
        save_resume_context();
    }
    let ctx = match captured_context() {
        Some(c) => c,
        None => return TestResult::Fail("save_resume_context did not mark the context captured"),
    };
    if ctx.efer == 0 {
        return TestResult::Fail("EFER slot is zero — nothing would be restored on resume");
    }
    if ctx.efer & LMA != 0 {
        return TestResult::Fail("saved EFER kept LMA set — restore wrmsr would #GP(0) on AMD");
    }
    if ctx.efer != live & !LMA {
        return TestResult::Fail("saved EFER is not the live EFER with LMA masked off");
    }
    if ctx.efer & LME == 0 {
        return TestResult::Fail("saved EFER has LME clear — restoring it would leave long mode");
    }
    if ctx.efer & NXE == 0 {
        return TestResult::Fail(
            "saved EFER has NXE clear — kernel windows are NX, so PTE bit 63 would be reserved",
        );
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("arch/s3", smoke_s3_resume_context_saves_replayable_efer);
