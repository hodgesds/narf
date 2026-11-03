//! Real independent AP beacons enter the private native-observation parser.
use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wifi_fixtures::{FakeAp, NetworkPlan};

fn domain() -> RegulatoryDomain {
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![narf_wireless::reg::RegRule {
            freq_start_mhz: 5170,
            freq_end_mhz: 5835,
            max_bandwidth_mhz: 80,
            max_power_dbm: 24,
            flags: narf_wireless::reg::RegFlags::empty(),
        }],
    }
}
fn native(frequency: u16) -> Management {
    let plan = NetworkPlan {
        station: [2, 3, 4, 5, 6, 7],
        bssid: [2, 8, 9, 10, 11, 12],
        server_ip: [10, 0, 0, 1],
        lease_ip: [10, 0, 0, 2],
        netmask: [255, 255, 255, 0],
        lease_seconds: 3600,
    };
    let channel = ((frequency - 5000) / 5) as u8;
    Management {
        channel: u32::from(channel),
        snr: 24,
        status: 0,
        frame: FakeAp::open(plan, b"narf", channel, 7).unwrap().beacon(),
    }
}
fn event(scan: u16, kind: u32, frequency: u32) -> ScanEvent {
    ScanEvent {
        kind,
        reason: 0,
        frequency,
        request: 0xa001,
        sequence: 0xa000 | u32::from(scan),
        vdev: 0,
    }
}
fn observe(owner: &mut Owner, sequence: u16, frequencies: &[u16]) -> Result<(), &'static str> {
    let mut scan = owner
        .begin(Factory::from_eeprom(0x64).unwrap(), sequence, frequencies)
        .ok_or("missing actual factory/policy scope")?;
    scan.event(&event(sequence, 1, 0), frequencies);
    for frequency in frequencies {
        scan.event(&event(sequence, 8, u32::from(*frequency)), frequencies);
        owner
            .observe(&scan, &native(*frequency), frequencies)
            .map_err(|_| "native Beacon decode")?;
    }
    Ok(())
}
fn smoke_ath10k_beacon_hint_requires_native_beacon_dwell_and_observed_constituents() -> TestResult {
    (|| {
        let database = Arc::new(db::Database::new());
        let policy = domain();
        database.install(policy.clone());
        let mut owner = Owner::scoped(database);
        let factory = Factory::from_eeprom(0x64).unwrap();
        let channels = [5180, 5200, 5220, 5240];
        let mut scan = owner
            .begin(factory, 1, &[5180])
            .ok_or("native scan scope")?;
        let valid = native(5180);
        owner
            .observe(&scan, &valid, &channels)
            .map_err(|_| "pre-start Beacon decode")?;
        scan.event(&event(1, 1, 0), &channels);
        owner
            .observe(&scan, &valid, &channels)
            .map_err(|_| "pre-FOREIGN Beacon decode")?;
        if owner
            .receipt(&policy)
            .is_none_or(|h| h.permits(factory, &policy, &[5180]))
        {
            return Err("Beacon before actual START/FOREIGN promoted World NO_IR");
        }
        scan.event(&event(1, 8, 5200), &channels);
        owner
            .observe(&scan, &native(5200), &channels)
            .map_err(|_| "unrequested dwell decode")?;
        scan.event(&event(1, 8, 5180), &channels);
        for negative in 0..5 {
            let mut bad = native(5180);
            match negative {
                0 => bad.frame[0] = 0x50, // Valid public probe response, never a hint.
                1 => bad.status = 1,
                2 => bad.channel = 40,
                3 => bad.frame[34] = (bad.frame[34] & !3) | 2, // IBSS, not ESS.
                _ => bad.frame.extend_from_slice(&[3, 1, 40]), // Contradicts native channel36.
            }
            owner
                .observe(&scan, &bad, &channels)
                .map_err(|_| "bounded invalid native frame")?;
            if owner
                .receipt(&policy)
                .is_none_or(|h| h.permits(factory, &policy, &[5180, 5200]))
                || owner
                    .receipt(&policy)
                    .is_some_and(|h| h.permits(factory, &policy, &[5180]))
            {
                return Err("probe/status/foreign/IBSS/contradictory channel minted a native hint");
            }
        }
        owner
            .observe(&scan, &valid, &channels)
            .map_err(|_| "genuine native Beacon")?;
        let first = owner.receipt(&policy).ok_or("native receipt")?;
        if !first.permits(factory, &policy, &[5180])
            || first.permits(factory, &policy, &[5180, 5200])
        {
            return Err("primary Beacon promoted unobserved occupied geometry");
        }
        let first = first
            .restrict(factory, &policy, &[5180])
            .ok_or("exact primary receipt")?;
        observe(&mut owner, 2, &channels)?;
        let wide = owner
            .receipt(&policy)
            .ok_or("four original native observations")?;
        if !wide.permits(factory, &policy, &channels)
            || wide.permits(factory, &policy, &[5745])
            || first.permits(factory, &policy, &[5200])
        {
            return Err("wider/fresh observation changed an older captured constituent mask");
        }
        let later = wide
            .restrict(factory, &policy, &[5180])
            .ok_or("same primary after neighbor Beacon")?;
        if first != later {
            return Err("irrelevant neighbor observation rebound an existing exact permission");
        }
        for sku in 0x60..=0x6c {
            if !world(Factory::from_eeprom(sku).map_err(|_| "known World factory")?) {
                return Err("eligible primary-source World SKU was lost");
            }
        }
        if world(Factory::from_eeprom(0x8348).unwrap())
            || world(Factory::from_eeprom(0x37).unwrap())
        {
            return Err("fixed/unresolved non-World factory became a roaming hint SKU");
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/beacon_hints",
    smoke_ath10k_beacon_hint_requires_native_beacon_dwell_and_observed_constituents
);

fn smoke_ath10k_beacon_hint_original_policy_arc_and_radio_cannot_be_recaptured() -> TestResult {
    (|| {
        let database = Arc::new(db::Database::new());
        let policy = domain();
        database.install(policy.clone());
        let factory = Factory::from_eeprom(0x64).unwrap();
        let mut owner = Owner::scoped(database.clone());
        observe(&mut owner, 1, &[5180])?;
        let original = owner.receipt(&policy).ok_or("original native witness")?;
        database.install(policy.clone()); // Equal bytes, distinct signed-policy generation.
        if original.permits(factory, &policy, &[5180]) || owner.receipt(&policy).is_some() {
            return Err("equal-byte policy replacement revived original hint authority");
        }
        let _ = owner.begin(factory, 2, &[5180]).ok_or("new policy scope")?;
        if owner
            .receipt(&policy)
            .is_some_and(|h| h.permits(factory, &policy, &[5180]))
        {
            return Err("new policy inherited public BSS/old native observations");
        }
        observe(&mut owner, 3, &[5180])?;
        let second = owner.receipt(&policy).ok_or("fresh actual Beacon")?;
        if !second.permits(factory, &policy, &[5180]) || original.permits(factory, &policy, &[5180])
        {
            return Err("new actual Beacon recaptured a retired policy receipt");
        }
        database.clear();
        database.install(policy.clone());
        if second.permits(factory, &policy, &[5180]) {
            return Err("policy removal/restoration revived old native hint");
        }
        observe(&mut owner, 4, &[5180])?;
        let current = owner.receipt(&policy).ok_or("current radio receipt")?;
        owner.retire();
        if current.permits(factory, &policy, &[5180]) || owner.begin(factory, 5, &[5180]).is_some()
        {
            return Err("retired physical radio recaptured its old observation");
        }
        let mut successor = Owner::scoped(database);
        if successor.receipt(&policy).is_some() {
            return Err("fresh radio inherited old hint");
        }
        observe(&mut successor, 1, &[5180])?;
        let fresh = successor
            .receipt(&policy)
            .ok_or("fresh radio actual Beacon")?;
        if !fresh.permits(factory, &policy, &[5180]) || current.permits(factory, &policy, &[5180]) {
            return Err("successor observation revived an old radio receipt");
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/beacon_hints",
    smoke_ath10k_beacon_hint_original_policy_arc_and_radio_cannot_be_recaptured
);

/// wireless-regdb `country US` shape around UNII-1/UNII-2: 5170–5250 plain,
/// 5250–5330 `DFS` (cfg80211 `IEEE80211_CHAN_RADAR`).
fn radar_domain(extra: narf_wireless::reg::RegFlags) -> RegulatoryDomain {
    use narf_wireless::reg::{RegFlags, RegRule};
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![
            RegRule {
                freq_start_mhz: 5170,
                freq_end_mhz: 5250,
                max_bandwidth_mhz: 80,
                max_power_dbm: 23,
                flags: RegFlags::empty(),
            },
            RegRule {
                freq_start_mhz: 5250,
                freq_end_mhz: 5330,
                max_bandwidth_mhz: 80,
                max_power_dbm: 23,
                flags: RegFlags::DFS | extra,
            },
        ],
    }
}
fn observe_with(
    owner: &mut Owner,
    factory: Factory,
    sequence: u16,
    frequencies: &[u16],
) -> Result<(), &'static str> {
    let mut scan = owner
        .begin(factory, sequence, frequencies)
        .ok_or("radar scan scope")?;
    scan.event(&event(sequence, 1, 0), frequencies);
    for frequency in frequencies {
        scan.event(&event(sequence, 8, u32::from(*frequency)), frequencies);
        owner
            .observe(&scan, &native(*frequency), frequencies)
            .map_err(|_| "native Beacon decode")?;
    }
    Ok(())
}
/// cfg80211 `beacon_found` on a RADAR channel admits only the station
/// client, only for heard constituents, and only until a newer scan of that
/// channel fails to hear it again. The non-client receipt never carries it.
fn smoke_ath10k_dfs_client_needs_radar_beacon_in_current_scan() -> TestResult {
    use crate::ath10k::regulatory::Permission;
    (|| {
        for (extra, factory) in [
            (narf_wireless::reg::RegFlags::empty(), 0x8348),
            (narf_wireless::reg::RegFlags::NO_IR, 0x8348),
            (narf_wireless::reg::RegFlags::empty(), 0x64),
        ] {
            let factory = Factory::from_eeprom(factory).map_err(|_| "factory")?;
            let database = Arc::new(db::Database::new());
            let policy = radar_domain(extra);
            database.install(policy.clone());
            let mut owner = Owner::scoped(database.clone());
            let permit = |hint, f, s, w| {
                Permission::factory_with_hint_for_test(factory, &policy, f, s, w, hint)
            };
            if permit(owner.client_receipt(&policy), 5260, None, false).is_ok() {
                return Err("radar channel admitted without any Beacon");
            }
            observe_with(&mut owner, factory, 1, &[5260])?;
            let client = owner.client_receipt(&policy).ok_or("client receipt")?;
            if owner.receipt(&policy).is_some_and(|r| r.radar_mask() != 0)
                || permit(owner.receipt(&policy), 5260, None, false).is_ok()
            {
                return Err("non-client (AP/probe/off-channel) receipt carried radar");
            }
            let p = permit(Some(client.clone()), 5260, None, false)
                .map_err(|_| "heard radar channel refused for the client")?;
            if p.radar == 0 || p.check(&policy).is_err() {
                return Err("radar permission lost its constituent or receipt");
            }
            if permit(Some(client.clone()), 5260, Some(5280), false).is_ok() {
                return Err("unheard radar secondary admitted");
            }
            observe_with(&mut owner, factory, 2, &[5260, 5280, 5300, 5320])?;
            let wide = owner.client_receipt(&policy).ok_or("wide receipt")?;
            let w = permit(Some(wide), 5260, Some(5280), true)
                .map_err(|_| "fully heard radar VHT80 refused")?;
            if w.center != 5290 || w.radar.count_ones() != 4 {
                return Err("radar VHT80 geometry");
            }
            // A newer scan of ch52 that hears nothing retracts the witness.
            let mut scan = owner.begin(factory, 3, &[5260]).ok_or("rescan")?;
            scan.event(&event(3, 1, 0), &[5260]);
            if permit(owner.client_receipt(&policy), 5260, None, false).is_ok() {
                return Err("stale radar witness survived a newer scan of it");
            }
            // Policy replacement closes previously issued radar permissions.
            database.install(policy.clone());
            if p.check(&policy).is_ok() || w.check(&policy).is_ok() {
                return Err("radar receipt outlived its policy generation");
            }
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/dfs",
    smoke_ath10k_dfs_client_needs_radar_beacon_in_current_scan
);
