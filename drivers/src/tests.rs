//! Subsystem smokes for `narf-drivers`.
//!
//! Migrated from `narf-verification`. Tests register under the
//! `drivers` subsystem.

extern crate alloc;

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_drivers_bound_firmware_round_trip() -> TestResult {
    use crate::{
        bound_firmware_of, bound_firmware_snapshot, record_bound,
        set_bound_firmware, BoundDriver, BoundFirmware, BoundKind,
    };
    record_bound(BoundDriver {
        name:    alloc::string::String::from("smoke-fw-driver"),
        kind:    BoundKind::Net,
        pci_vid: Some(0x17CB),
        pci_did: Some(0x1103),
        domain:  BoundKind::Net.default_domain(),
    });
    let fw = BoundFirmware {
        blob_name: alloc::string::String::from("vendor/smoke/blob.bin"),
        sha256:    [0xAB; 32],
        signer:    None,
        version:   Some(alloc::string::String::from("1.2.3")),
    };
    let bound_found = set_bound_firmware("smoke-fw-driver", fw.clone());
    if !bound_found {
        return TestResult::Fail("set_bound_firmware didn't see the bound driver");
    }
    let recovered = match bound_firmware_of("smoke-fw-driver") {
        Some(f) => f,
        None    => return TestResult::Fail("firmware_of missed entry"),
    };
    if recovered.blob_name != "vendor/smoke/blob.bin" {
        return TestResult::Fail("blob_name round-trip");
    }
    if recovered.sha256 != [0xAB; 32] {
        return TestResult::Fail("sha256 round-trip");
    }
    if recovered.version.as_deref() != Some("1.2.3") {
        return TestResult::Fail("version round-trip");
    }
    if !bound_firmware_snapshot().iter().any(|(n, _)| n == "smoke-fw-driver") {
        return TestResult::Fail("snapshot missed entry");
    }
    TestResult::Pass
}
kernel_test_in!("drivers", smoke_drivers_bound_firmware_round_trip);

#[cfg(target_arch = "x86_64")]
fn smoke_drivers_claim_mmio_in_domain() -> TestResult {
    use narf_arch::x86_64::pcid;
    use crate::claim_mmio_in_domain;
    use narf_memory::frame::alloc_frame;
    use narf_memory::paging::PtFlags;
    use narf_memory::domain::{cross_domain_slot_present, domain_va_base};

    if !pcid::is_active() {
        return TestResult::Skip("PCID enforcer not active (PKS-class CPU)");
    }

    let frame = match alloc_frame() {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("alloc_frame failed"),
    };
    let pa = frame.start_address().raw();
    let domain: u8 = 5;

    // SAFETY: pa is a frame we just allocated; flags are MMIO-style.
    let va_base = match unsafe {
        claim_mmio_in_domain(
            domain,
            pa,
            4096,
            PtFlags::PRESENT | PtFlags::WRITABLE | PtFlags::NO_CACHE,
        )
    } {
        Ok(v)  => v,
        Err(_) => return TestResult::Fail("claim_mmio_in_domain failed"),
    };

    let slot_base = domain_va_base(domain).unwrap_or(0);
    let slot_end  = slot_base + (1u64 << 39);
    if va_base < slot_base || va_base >= slot_end {
        return TestResult::Fail("VA escaped domain slot");
    }

    for inspector in 0u8..16 {
        if inspector == domain { continue; }
        match cross_domain_slot_present(inspector, domain) {
            Some(true)  => return TestResult::Fail("cross-domain slot leaked after claim"),
            Some(false) => {}
            None        => return TestResult::Fail("PML4 missing"),
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("drivers", smoke_drivers_claim_mmio_in_domain);

fn smoke_drivers_default_domain_policy() -> TestResult {
    use crate::BoundKind;
    if BoundKind::Block.default_domain()  != 1 { return TestResult::Fail("Block != 1");  }
    if BoundKind::Net.default_domain()    != 2 { return TestResult::Fail("Net != 2");    }
    if BoundKind::UsbHost.default_domain()!= 3 { return TestResult::Fail("UsbHost != 3");}
    if BoundKind::Rng.default_domain()    != 4 { return TestResult::Fail("Rng != 4");    }
    if BoundKind::Balloon.default_domain()!= 5 { return TestResult::Fail("Balloon != 5");}
    if BoundKind::Other.default_domain()  !=15 { return TestResult::Fail("Other != 15"); }
    TestResult::Pass
}
kernel_test_in!("drivers", smoke_drivers_default_domain_policy);

fn smoke_drivers_set_domain_override() -> TestResult {
    use alloc::string::String;
    use crate::{record_bound, BoundDriver, BoundKind,
                       set_driver_domain, driver_domain};
    let name = String::from("__test_driver_domain__");
    record_bound(BoundDriver {
        name:    name.clone(),
        kind:    BoundKind::Block,
        pci_vid: None,
        pci_did: None,
        domain:  BoundKind::Block.default_domain(),
    });
    if driver_domain(&name) != Some(1) {
        return TestResult::Fail("default Block domain didn't take");
    }
    if !set_driver_domain(&name, 7) {
        return TestResult::Fail("set_driver_domain returned false");
    }
    if driver_domain(&name) != Some(7) {
        return TestResult::Fail("override didn't stick");
    }
    TestResult::Pass
}
kernel_test_in!("drivers", smoke_drivers_set_domain_override);

#[cfg(target_arch = "x86_64")]
fn smoke_drivers_release_and_reuse_domain_va() -> TestResult {
    use narf_arch::x86_64::pcid;
    use crate::{
        claim_mmio_in_domain, free_chunks_in_domain, release_domain_mmio,
    };
    use narf_memory::frame::alloc_frame;
    use narf_memory::paging::PtFlags;

    if !pcid::is_active() {
        return TestResult::Skip("PCID enforcer not active (PKS-class CPU)");
    }
    let domain: u8 = 7;
    let frame = match alloc_frame() { Ok(f) => f, Err(_) => return TestResult::Fail("alloc_frame") };
    let pa = frame.start_address().raw();

    let before = free_chunks_in_domain(domain);
    // SAFETY: pa is a fresh frame; flags are MMIO-style.
    let va1 = match unsafe {
        claim_mmio_in_domain(domain, pa, 4096,
            PtFlags::PRESENT | PtFlags::WRITABLE | PtFlags::NO_CACHE)
    } { Ok(v) => v, Err(_) => return TestResult::Fail("claim 1") };

    // SAFETY: matched claim above.
    if unsafe { release_domain_mmio(domain, va1, 4096) }.is_err() {
        return TestResult::Fail("release failed");
    }
    if free_chunks_in_domain(domain) != before + 1 {
        return TestResult::Fail("free-list did not grow on release");
    }

    // SAFETY: same shape as the first claim.
    let va2 = match unsafe {
        claim_mmio_in_domain(domain, pa, 4096,
            PtFlags::PRESENT | PtFlags::WRITABLE | PtFlags::NO_CACHE)
    } { Ok(v) => v, Err(_) => return TestResult::Fail("claim 2") };

    if free_chunks_in_domain(domain) != before {
        return TestResult::Fail("free-list did not shrink on reuse");
    }
    if va2 != va1 {
        return TestResult::Fail("reuse didn't return the same VA");
    }
    let _ = unsafe { release_domain_mmio(domain, va2, 4096) };
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("drivers", smoke_drivers_release_and_reuse_domain_va);

fn smoke_drivers_register_and_lifecycle() -> TestResult {
    use crate::{
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
kernel_test_in!("drivers", smoke_drivers_register_and_lifecycle);

fn smoke_drivers_register_revoked_authority() -> TestResult {
    use crate::{
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
kernel_test_in!("drivers", smoke_drivers_register_revoked_authority);

fn smoke_drivers_dedicated_domain_exhaustion() -> TestResult {
    use crate::{
        DomainPolicy, DriverManifest, NoopDriver, RegistrationError,
        bootstrap_authority, registry,
    };

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
kernel_test_in!("drivers", smoke_drivers_dedicated_domain_exhaustion);

fn smoke_param_slot_not_installed() -> TestResult {
    // ParamSlot.read on an empty slot returns NotInstalled, not UB.
    use narf_capabilities::{Cap, Read};
    use crate::{DriverHandle, DriverParams, ParamError, ParamSlot};

    #[derive(Debug)]
    struct Empty;
    #[derive(Copy, Clone, Debug)] struct EmptySnap;
    #[derive(Copy, Clone, Debug)] struct EmptyUpd;
    impl DriverParams for Empty {
        type Snapshot = EmptySnap; type Update = EmptyUpd;
        fn snapshot(&self) -> EmptySnap { EmptySnap }
        fn apply(&mut self, _: EmptyUpd) -> Result<(), ParamError> { Ok(()) }
    }
    static SLOT: ParamSlot<Empty> = ParamSlot::new();
    SLOT.__reset_for_test();
    let cap: Cap<DriverHandle, Read> = Cap::bootstrap();
    match SLOT.read(&cap) {
        Err(ParamError::NotInstalled) => TestResult::Pass,
        _                              => TestResult::Fail("expected NotInstalled"),
    }
}
kernel_test_in!("drivers", smoke_param_slot_not_installed);
