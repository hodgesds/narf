// SPDX-License-Identifier: GPL-2.0-or-later
//! Native CE/HTT Beacon observations; public BSS records are never authority.
use super::*;
use core::sync::atomic::{AtomicUsize, Ordering};
use narf_wireless::reg::{db::Database, RegFlags, RegulatoryDomain};

fn scoped(
    version: u32,
    dialect: Dialect,
    secured: bool,
    policy: Option<RegulatoryDomain>,
) -> (Harness, Arc<Database>) {
    let database = Arc::new(Database::new());
    database.install(policy.unwrap_or_else(five_ghz_policy));
    let hardware = if dialect == Dialect::Tlv {
        HwRev::Qca6174
    } else if dialect == Dialect::TenFour {
        HwRev::Qca9984
    } else {
        HwRev::Qca988x
    };
    let harness = Harness::new_on_snapshot(
        version,
        dialect,
        secured,
        false,
        5180,
        0x64,
        (
            NativeFirmware {
                ht: None,
                radio: RadioSource {
                    hardware,
                    rf_chains: 2,
                    vht: None,
                },
                all_inventory: false,
                features: (1 << 10) | (1 << 2) | if dialect == Dialect::Tlv { 1 << 18 } else { 0 },
                htt: (3, 1),
                hardware_keys: false,
                nlo: false,
            },
            Some(database.clone()),
        ),
    );
    (harness, database)
}
pub(super) fn harness(
    version: u32,
    dialect: Dialect,
    secured: bool,
    policy: Option<RegulatoryDomain>,
) -> Harness {
    scoped(version, dialect, secured, policy).0
}

fn smoke_ath10k_world_beacon_native_six_dialects_open_wpa2_dhcp_ip() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        for secured in [false, true] {
            if let Err(error) = composition_radio(
                version,
                dialect,
                secured,
                false,
                false,
                5180,
                TestPhy::BeaconHint,
            ) {
                return TestResult::Fail(error);
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/regulatory/beacon",
    smoke_ath10k_world_beacon_native_six_dialects_open_wpa2_dhcp_ip
);

fn smoke_ath10k_world_public_bss_or_unowned_dwell_never_grants_emission() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        for observation in [
            BeaconHintFixture::Probe,
            BeaconHintFixture::NoForeign,
            BeaconHintFixture::WrongScope,
            BeaconHintFixture::WrongChannel,
        ] {
            let h = harness(version, dialect, true, None);
            h.model(|m| m.beacon_hint = observation);
            if let Err(error) = h.scan() {
                return TestResult::Fail(error);
            }
            // The normal native parser really returned the same AP/BSS. Only
            // its emission authority differs; no fabricated public BSS enters.
            let before = h.model(|m| (m.sent.len(), m.native_management.len()));
            if !matches!(
                drive(h.device.associate_for_test(h.request(), [0x73; 32])),
                Poll::Ready(Err(_))
            ) || !h.never_opened()
                || h.model(|m| (m.sent.len(), m.native_management.len())) != before
            {
                return TestResult::Fail("public BSS or foreign scan scope lifted World NO_IR");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/regulatory/beacon",
    smoke_ath10k_world_public_bss_or_unowned_dwell_never_grants_emission
);

fn smoke_ath10k_world_beacon_keeps_host_flags_overlap_and_unobserved_span_denied() -> TestResult {
    for flags in [
        RegFlags::NO_IR,
        RegFlags::DFS,
        RegFlags::INDOOR_ONLY,
        RegFlags::DEPLOYMENT_INDOOR,
        RegFlags::from_bits_retain(1 << 31),
    ] {
        let mut policy = five_ghz_policy();
        policy.rules[1].flags = flags;
        let h = harness(4, Dialect::Tlv, false, Some(policy));
        if let Err(error) = h.scan() {
            return TestResult::Fail(error);
        }
        let before = h.model(|m| m.sent.len());
        if !matches!(
            drive(h.device.associate_for_test(h.request(), [0x73; 32])),
            Poll::Ready(Err(_))
        ) || !h.never_opened()
            || h.model(|m| m.sent.len()) != before
        {
            return TestResult::Fail("native Beacon erased a signed host restriction");
        }
    }
    let mut policy = five_ghz_policy();
    policy.rules.push(narf_wireless::reg::RegRule {
        freq_start_mhz: 5175,
        freq_end_mhz: 5185,
        max_bandwidth_mhz: 10,
        max_power_dbm: 1,
        flags: RegFlags::empty(),
    });
    let h = harness(4, Dialect::Tlv, false, Some(policy));
    let before = h.model(|m| m.sent.len());
    if h.scan().is_ok() || !h.never_opened() || h.model(|m| m.sent.len()) != before {
        return TestResult::Fail("World hint bypassed an overlapping host span");
    }
    drop(h);
    let (h, database) = scoped(4, Dialect::Tlv, true, None);
    let policy = database.snapshot().unwrap();
    if h.device
        .radio
        .try_lock()
        .unwrap()
        .active_frequency_allowed(&policy, 5180)
    {
        return TestResult::Fail("unobserved World channel started active");
    }
    if let Err(error) = h.join() {
        return TestResult::Fail(error);
    }
    let radio = h.device.radio.try_lock().unwrap();
    if !radio.active_frequency_allowed(&policy, 5180)
        || crate::ath10k::regulatory::Permission::from_domain(
            radio.htt.wmi.caps.as_ref().unwrap(),
            &policy,
            5180,
        )
        .is_ok()
        || radio.active_frequency_allowed(&policy, 5200)
        || radio
            .prepare_active_scan(&[5180, 5200], &[b"narf".to_vec()], &policy)
            .is_ok()
        || radio
            .prepared_peer()
            .is_none_or(|peer| peer.bandwidth_mhz != 20)
    {
        return TestResult::Fail("one native Beacon lent an unobserved occupied span");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/regulatory/beacon",
    smoke_ath10k_world_beacon_keeps_host_flags_overlap_and_unobserved_span_denied
);

fn smoke_ath10k_world_beacon_original_policy_epoch_fences_wait_and_copied_data() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        {
            let (h, database) = scoped(version, dialect, true, None);
            h.model(|m| {
                let f = m.data.as_mut().unwrap();
                f.wmm_offer = Some(WMM_PARAMETERS.to_vec());
                f.wmm_response = Some(WMM_PARAMETERS.to_vec());
                f.wmm_hold = true;
            });
            if let Err(error) = h.scan() {
                return TestResult::Fail(error);
            }
            let original = database.snapshot().unwrap();
            let mut future = core::pin::pin!(h.device.associate_for_test(h.request(), [0x73; 32]));
            if !drive(future.as_mut()).is_pending() {
                return TestResult::Fail("World receipt did not retain actual native credit wait");
            }
            database.install(original.as_ref().clone());
            if !matches!(drive(future.as_mut()), Poll::Ready(Err(_))) || !h.never_opened() {
                return TestResult::Fail(
                    "original World receipt survived policy replacement in wait",
                );
            }
        }
        let (h, database) = scoped(version, dialect, true, None);
        if let Err(error) = h.scan() {
            return TestResult::Fail(error);
        }
        let original = database.snapshot().unwrap();
        let plan = match h.device.radio.try_lock().unwrap().prepare_active_scan(
            &[5180],
            &[b"narf".to_vec()],
            &original,
        ) {
            Ok(plan) => plan,
            Err(_) => return TestResult::Fail("real Beacon did not create an original plan"),
        };
        database.install(original.as_ref().clone());
        {
            let radio = h.device.radio.try_lock().unwrap();
            if plan
                .validate(radio.htt.wmi.caps.as_ref().unwrap(), &original)
                .is_ok()
                || radio.active_frequency_allowed(&original, 5180)
            {
                return TestResult::Fail("equal policy bytes recaptured an old Beacon receipt");
            }
        }
        // A fresh actual native scan may admit a new owner, never revive plan.
        if let Err(error) = h.join() {
            return TestResult::Fail(error);
        }
        {
            let radio = h.device.radio.try_lock().unwrap();
            if plan
                .validate(radio.htt.wmi.caps.as_ref().unwrap(), &original)
                .is_ok()
            {
                return TestResult::Fail("new Beacon revived a retired original plan");
            }
        }
        let reached = Arc::new(AtomicUsize::new(0));
        let count = reached.clone();
        let current = database.clone();
        let replacement = original.as_ref().clone();
        h.device.set_receive_hook_for_test(move |point| {
            if point == crate::ath10k::interface::ReceivePoint::AfterFrameAllocation {
                count.fetch_add(1, Ordering::AcqRel);
                current.install(replacement.clone());
            }
        });
        let (_, down) = packets();
        h.model(|m| {
            let f = m.data.as_mut().unwrap();
            let bytes = f.downlink(&down);
            f.queue.push_back(bytes);
        });
        let before = narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets;
        h.pump();
        if reached.load(Ordering::Acquire) != 1
            || !h.closed()
            || h.received(&down)
            || narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != before
            || !h.model(|m| {
                m.inner.inner.retained.is_some()
                    && m.inner
                        .storage
                        .as_ref()
                        .is_some_and(|storage| storage.filled == 1023)
            })
        {
            return TestResult::Fail("policy epoch replacement crossed copied DATA publication");
        }
        database.install(original.as_ref().clone());
        let (up, _) = packets();
        if !h.closed() || h.device.enqueue(&up, narf_net::TxMeta::plain()).is_ok() {
            return TestResult::Fail("restored policy resurrected retired native hint authority");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/regulatory/beacon",
    smoke_ath10k_world_beacon_original_policy_epoch_fences_wait_and_copied_data
);
