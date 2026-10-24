use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

include!("policy_fixture.rs");

fn signed_blob() -> alloc::vec::Vec<u8> {
    let mut bytes = PAYLOAD.to_vec();
    bytes.extend_from_slice(&SIGNATURE);
    bytes.extend_from_slice(&FINGERPRINT);
    bytes.extend_from_slice(&[0; 4]); // no optional metadata
    bytes.extend_from_slice(b"NRFW");
    bytes
}

fn registry() -> Cap<FirmwareRegistry, Read> {
    let (write, read) = narf_firmware::bootstrap_authority();
    // The public test key is installed only by this kernel-test function.
    // The test name cannot shadow the real deployment-policy registry key.
    narf_firmware::register_trusted_signer(FINGERPRINT, PUBLIC);
    narf_firmware::install("test/wireless-policy-signed", &signed_blob(), &write)
        .expect("independent policy signature installs under isolated test name");
    read
}

fn exact(domain: &RegulatoryDomain) -> bool {
    domain.country_code == *b"US"
        && domain.rules.len() == 1
        && domain.rules[0].freq_start_mhz == 2402
        && domain.rules[0].freq_end_mhz == 2472
        && domain.rules[0].max_bandwidth_mhz == 20
        && domain.rules[0].max_power_dbm == 17
        && domain.rules[0].flags.is_empty()
}

fn smoke_signed_regulatory_bootstrap_uses_real_registry_and_current_invocation() -> TestResult {
    let authority = registry();
    let blob = match narf_firmware::open("test/wireless-policy-signed", &authority) {
        Ok(blob) => blob,
        Err(_) => return TestResult::Fail("signed policy could not be opened"),
    };
    match blob.invoke(ReadPolicy) {
        Ok(Ok(domain)) if exact(&domain) => {}
        _ => return TestResult::Fail("signed policy invocation changed deployment rules"),
    }
    blob.revoke();
    if blob.invoke(ReadPolicy).is_ok() {
        return TestResult::Fail("revoked regulatory blob was decoded outside invocation");
    }
    authority.revoke();
    if load_from(&authority, "test/wireless-policy-signed").is_ok() {
        return TestResult::Fail("revoked registry authority loaded regulatory policy");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/regulatory",
    smoke_signed_regulatory_bootstrap_uses_real_registry_and_current_invocation
);

fn smoke_regulatory_bootstrap_independent_of_other_driver_initialization() -> TestResult {
    let authority = registry();
    let database = IrqSafeSpinLock::new(None);
    let calls = core::cell::Cell::new(0);
    let load = || {
        calls.set(calls.get() + 1);
        // Resolving a firmware capability must not happen under the DB lock.
        let Some(guard) = database.try_lock() else {
            return Err(Error::Authority);
        };
        if guard.is_some() {
            return Err(Error::Authority);
        }
        drop(guard);
        load_from(&authority, "test/wireless-policy-signed")
    };
    match super::super::db::ensure_with(&database, load) {
        Ok(domain) if exact(&domain) && calls.get() == 1 => {}
        _ => return TestResult::Fail("standalone signed bootstrap required another driver"),
    }
    // The installed caller policy remains usable without another firmware
    // lookup; callers retain the same cache contract as set_domain/get_domain.
    match super::super::db::ensure_with(&database, || {
        calls.set(calls.get() + 1);
        Err(Error::Authority)
    }) {
        Ok(domain) if exact(&domain) && calls.get() == 1 => TestResult::Pass,
        _ => TestResult::Fail("cached domain unnecessarily depended on firmware/driver order"),
    }
}
kernel_test_in!(
    "wireless/regulatory",
    smoke_regulatory_bootstrap_independent_of_other_driver_initialization
);

fn smoke_regulatory_bootstrap_rejects_unsigned_invalid_and_missing_assets() -> TestResult {
    if !matches!(decode(&PAYLOAD, None), Err(Error::Unsigned)) {
        return TestResult::Fail("unsigned developer firmware granted regulatory authority");
    }
    let authority = registry();
    if load_from(&authority, "test/wireless-policy-absent").is_ok() {
        return TestResult::Fail("missing deployment policy became an inferred default");
    }
    let mut malformed = PAYLOAD;
    malformed[25] = 0x80;
    if !matches!(decode(&malformed, Some(FINGERPRINT)), Err(Error::Format(_))) {
        return TestResult::Fail("invalid signed policy rules were accepted");
    }
    for error in [
        Error::Authority,
        Error::Unsigned,
        Error::Format("test invalid policy"),
    ] {
        let database = IrqSafeSpinLock::new(None);
        if !matches!(super::super::db::ensure_with(&database, || Err(error)), Err(e) if e == error)
            || database.lock().is_some()
        {
            return TestResult::Fail("failed policy bootstrap published partial/default domain");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/regulatory",
    smoke_regulatory_bootstrap_rejects_unsigned_invalid_and_missing_assets
);

fn smoke_regulatory_bootstrap_preserves_policy_installed_during_lookup() -> TestResult {
    let database = IrqSafeSpinLock::new(None);
    let mut caller = parse_policy(&PAYLOAD).unwrap();
    caller.country_code = *b"CA";
    let result = super::super::db::ensure_with(&database, || {
        let Some(mut guard) = database.try_lock() else {
            return Err(Error::Authority);
        };
        *guard = Some(caller);
        drop(guard);
        decode(&PAYLOAD, Some(FINGERPRINT))
    });
    match result {
        Ok(domain)
            if domain.country_code == *b"CA"
                && database
                    .lock()
                    .as_ref()
                    .is_some_and(|d| d.country_code == *b"CA") =>
        {
            TestResult::Pass
        }
        _ => TestResult::Fail("bootstrap overwrote caller policy racing firmware lookup"),
    }
}
kernel_test_in!(
    "wireless/regulatory",
    smoke_regulatory_bootstrap_preserves_policy_installed_during_lookup
);
