use super::super::db::Database;
use super::*;
use alloc::sync::Arc;
use narf_kernel_test::{kernel_test_in, TestResult};

include!("policy_fixture.rs");
include!("indoor_fixture.rs");

fn smoke_linux_regulatory_bootstrap_only_on_absence_and_country_source_guard() -> TestResult {
    use super::super::db::{ensure_source_with, select_linux_with, Source};
    let authority = registry();
    let db = narf_firmware::linux_regulatory_database();
    let Ok((world, Source::Linux(0))) = bootstrap_from(&authority, "test/absent-linux-policy", db)
    else {
        return TestResult::Fail("missing NRGD did not select authenticated Linux world");
    };
    if world.country_code != *b"00" || world.rule_for(2412).is_none() {
        return TestResult::Fail("Linux bootstrap did not retain world country/rules");
    }
    match bootstrap_from(&authority, "test/wireless-policy-signed", db) {
        Ok((domain, Source::Deployment)) if exact(&domain) => {}
        _ => return TestResult::Fail("Linux default displaced signed deployment policy"),
    }
    let database = Database::new();
    ensure_source_with(&database, || Ok((world.clone(), Source::Linux(0)))).unwrap();
    let linux_country = || super::super::linux::country(db, *b"US").map_err(Error::Format);
    if select_linux_with(&database, linux_country).is_err()
        || database.snapshot().unwrap().country_code != *b"US"
    {
        return TestResult::Fail("authenticated Linux country could not replace Linux world");
    }
    for deployment in [false, true] {
        database.clear();
        if deployment {
            ensure_source_with(&database, || Ok((world.clone(), Source::Deployment))).unwrap();
        } else {
            database.install(world.clone());
        }
        let called = core::cell::Cell::new(false);
        if select_linux_with(&database, || {
            called.set(true);
            linux_country()
        }) != Err(Error::Authority)
            || called.get()
        {
            return TestResult::Fail("country hint relaxed deployment/caller bounds");
        }
    }
    database.clear();
    ensure_source_with(&database, || Ok((world.clone(), Source::Linux(0)))).unwrap();
    if select_linux_with(&database, || {
        database.install(world.clone());
        linux_country()
    }) != Err(Error::Authority)
        || database.snapshot().unwrap().country_code != *b"00"
    {
        return TestResult::Fail("country lookup overwrote racing caller installation");
    }
    database.clear();
    ensure_source_with(&database, || Ok((world, Source::Linux(0)))).unwrap();
    if select_linux_with(&database, || {
        database.clear();
        linux_country()
    }) != Err(Error::Authority)
        || database.snapshot().is_some()
    {
        return TestResult::Fail("country lookup undid racing policy clear");
    }
    authority.revoke();
    if bootstrap_from(&authority, "test/absent-linux-policy", db).is_ok() {
        return TestResult::Fail("revoked lookup authority silently became Linux default");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/regulatory",
    smoke_linux_regulatory_bootstrap_only_on_absence_and_country_source_guard
);

fn smoke_signed_indoor_installation_requires_real_signature_and_current_blob() -> TestResult {
    let (write, read) = narf_firmware::bootstrap_authority();
    narf_firmware::register_trusted_signer(FINGERPRINT, PUBLIC);
    let mut signed = INDOOR_PAYLOAD.to_vec();
    signed.extend_from_slice(&INDOOR_SIGNATURE);
    signed.extend_from_slice(&FINGERPRINT);
    signed.extend_from_slice(&[0; 4]);
    signed.extend_from_slice(b"NRFW");
    if narf_firmware::install("test/wireless-indoor-signed", &signed, &write).is_err() {
        return TestResult::Fail("independently signed indoor policy was rejected");
    }
    let domain = match load_from(&read, "test/wireless-indoor-signed") {
        Ok(domain) => domain,
        Err(_) => return TestResult::Fail("signed indoor policy did not use actual firmware load"),
    };
    if domain.country_code != *b"US"
        || domain.rules.len() != 1
        || domain.rules[0].freq_start_mhz != 5170
        || domain.rules[0].freq_end_mhz != 5250
        || domain.rules[0].max_bandwidth_mhz != 80
        || domain.rules[0].max_power_dbm != 27
        || domain.rules[0].flags.bits() != 0x82
    {
        return TestResult::Fail("indoor assertion altered signed country, span or power");
    }
    if !matches!(decode(&INDOOR_PAYLOAD, None), Err(Error::Unsigned)) {
        return TestResult::Fail("unsigned indoor assertion supplied policy authority");
    }
    // Strip the installation assertion without changing its old signature.
    signed[25] = 2;
    if narf_firmware::install("test/wireless-indoor-tampered", &signed, &write).is_ok() {
        return TestResult::Fail("modified installation fact retained signature authority");
    }
    let blob = narf_firmware::open("test/wireless-indoor-signed", &read).unwrap();
    blob.revoke();
    if blob.invoke(ReadPolicy).is_ok() {
        return TestResult::Fail("revoked indoor blob was read outside current invocation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/regulatory",
    smoke_signed_indoor_installation_requires_real_signature_and_current_blob
);

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
    let database = Database::new();
    let calls = core::cell::Cell::new(0);
    let load = || {
        calls.set(calls.get() + 1);
        // Resolving a firmware capability must not happen under the DB lock.
        let Some(guard) = database.state.try_lock() else {
            return Err(Error::Authority);
        };
        if guard.domain.is_some() {
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
        let database = Database::new();
        if !matches!(super::super::db::ensure_with(&database, || Err(error)), Err(e) if e == error)
            || database.snapshot().is_some()
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
    let database = Database::new();
    let mut caller = parse_policy(&PAYLOAD).unwrap();
    caller.country_code = *b"CA";
    let result = super::super::db::ensure_with(&database, || {
        let Some(guard) = database.state.try_lock() else {
            return Err(Error::Authority);
        };
        drop(guard);
        database.install(caller);
        decode(&PAYLOAD, Some(FINGERPRINT))
    });
    match result {
        Ok(domain)
            if domain.country_code == *b"CA"
                && database
                    .snapshot()
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

fn smoke_regulatory_immutable_snapshots_replace_clear_and_isolate() -> TestResult {
    let database = Database::new();
    let isolated = Database::new();
    let domain = decode(&PAYLOAD, Some(FINGERPRINT)).unwrap();
    database.install(domain.clone());
    let old = database.snapshot().unwrap();
    if !Arc::ptr_eq(&old, &database.snapshot().unwrap()) || isolated.snapshot().is_some() {
        return TestResult::Fail("policy identity or isolated database ownership changed");
    }
    let mut changed = domain;
    changed.rules[0].max_power_dbm = 10;
    database.install(changed);
    let new = database.snapshot().unwrap();
    if Arc::ptr_eq(&old, &new) || !exact(&old) || new.rules[0].max_power_dbm != 10 {
        return TestResult::Fail("policy replacement mutated a retained immutable snapshot");
    }
    database.clear();
    if database.snapshot().is_some() || !exact(&old) || new.rules[0].max_power_dbm != 10 {
        return TestResult::Fail("clear kept current authority or invalidated retained storage");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/regulatory",
    smoke_regulatory_immutable_snapshots_replace_clear_and_isolate
);

fn smoke_regulatory_clear_wins_over_inflight_signed_bootstrap() -> TestResult {
    let database = Database::new();
    let loaded = super::super::db::ensure_with(&database, || {
        database.clear();
        decode(&PAYLOAD, Some(FINGERPRINT))
    });
    if !matches!(loaded, Err(Error::Authority)) || database.snapshot().is_some() {
        return TestResult::Fail("in-flight signed loader undid an intervening policy clear");
    }
    // A later explicit bootstrap is independent work, not the stale loader.
    if super::super::db::ensure_with(&database, || decode(&PAYLOAD, Some(FINGERPRINT))).is_err() {
        return TestResult::Fail("fresh bootstrap after clear was incorrectly prohibited");
    }
    database.clear();
    database.state.lock().revision = u64::MAX;
    if !matches!(
        super::super::db::ensure_with(&database, || decode(&PAYLOAD, Some(FINGERPRINT))),
        Err(Error::Authority)
    ) {
        return TestResult::Fail("exhausted policy revision admitted bootstrap ABA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/regulatory",
    smoke_regulatory_clear_wins_over_inflight_signed_bootstrap
);
