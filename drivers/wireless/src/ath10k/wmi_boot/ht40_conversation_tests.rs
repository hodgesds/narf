//! Actual CE/HTT/RSNA/netdev HT40 conversations. No native encoder supplies
//! the model's expected channel/peer words, PPDU facts or Ethernet bytes.
use super::*;
use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, Ordering};
use narf_wireless::reg::{RegFlags, RegRule};

fn secondary(f: u16) -> Option<u16> {
    Some(match f {
        5180 => 5200,
        5200 => 5180,
        5220 => 5240,
        5240 => 5220,
        5745 => 5765,
        5765 => 5745,
        5785 => 5805,
        5805 => 5785,
        _ => return None,
    })
}
fn elements(primary: u8, plus: bool) -> Vec<u8> {
    let mut v = vec![45, 26, 0x6e, 0, 0x1b, 0xff];
    v.extend_from_slice(&[0; 11]);
    v.push(1);
    v.extend_from_slice(&[0; 10]);
    v.extend_from_slice(&[61, 22, primary, if plus { 5 } else { 7 }]);
    v.extend_from_slice(&[0; 20]);
    v
}
pub(super) fn enable(h: &Harness) -> Result<(), &'static str> {
    let s = secondary(h.frequency).ok_or("HT40 test primary")?;
    ht_conversation_tests::enable(h);
    for rule in &mut h.policy.lock().as_mut().unwrap().rules {
        if rule.freq_start_mhz > 3000 {
            rule.max_bandwidth_mhz = 40;
        }
    }
    let ies = elements(h.request().channel as u8, s > h.frequency);
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        f.ht_offer = Some(ies.clone());
        f.ht_response = Some(ies);
        f.ht_secondary = Some(s);
        f.ht_capabilities = 0x006e;
        f.ht_sgi = false; // LGI40, independent of advertised RX SGI20.
        f.rx_phy = Some((8, 0x87, 0));
    });
    Ok(())
}
fn harness(secured: bool, f: u16) -> Result<Harness, &'static str> {
    let h = Harness::new_on(4, Dialect::Tlv, secured, false, f, 0x8348);
    enable(&h)?;
    Ok(h)
}
fn restriction(
    policy: &mut narf_wireless::reg::RegulatoryDomain,
    secondary: u16,
    flags: RegFlags,
    width: u32,
) {
    policy.rules.push(RegRule {
        freq_start_mhz: u32::from(secondary) - 1,
        freq_end_mhz: u32::from(secondary) + 1,
        max_bandwidth_mhz: width,
        max_power_dbm: 27,
        flags,
    });
}
fn rx(h: &Harness, bytes: Vec<u8>, sig: u32, guard: u32) {
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        f.rx_phy = Some((8, sig, guard));
        f.queue.push_back(bytes);
    });
    h.pump();
}
fn smoke_ath10k_ht40_native_six_dialects_open_wpa2_dhcp_ip_ps_and_retirement() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        for frequency in [5180, 5200] {
            for secured in [false, true] {
                if let Err(e) = composition_radio(
                    version,
                    dialect,
                    secured,
                    false,
                    true,
                    frequency,
                    TestPhy::Ht40,
                ) {
                    return TestResult::Fail(e);
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht40",
    smoke_ath10k_ht40_native_six_dialects_open_wpa2_dhcp_ip_ps_and_retirement
);

fn smoke_ath10k_ht40_all_qualified_pairs_keep_primary_center_and_native_inventory() -> TestResult {
    for primary in [5180, 5200, 5220, 5240, 5745, 5765, 5785, 5805] {
        let result = (|| {
            let h = harness(true, primary)?;
            h.join()?;
            let prepared = h
                .device
                .radio
                .try_lock()
                .unwrap()
                .prepared_peer()
                .ok_or("HT40 native peer absent")?;
            if prepared.frequency != primary
                || prepared.center_frequency != (primary + secondary(primary).unwrap()) / 2
                || prepared.bandwidth_mhz != 40
                || !h.model(|m| m.data.as_ref().unwrap().ht_inventory == 1)
            {
                return Err("HT40 primary/center/occupied native owner mismatch");
            }
            let (up, down) = packets();
            narf_net::iface::send_on(&h.name, &up).map_err(|_| "HT40 pair uplink")?;
            h.pump();
            let p = h.model(|m| m.data.as_mut().unwrap().downlink(&down));
            rx(&h, p, 0x87, 0);
            if !h.received(&down) || !h.model(|m| m.data.as_ref().unwrap().uplink.contains(&up)) {
                return Err("HT40 qualified pair native Ethernet");
            }
            Ok(())
        })();
        if let Err(e) = result {
            return TestResult::Fail(e);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht40",
    smoke_ath10k_ht40_all_qualified_pairs_keep_primary_center_and_native_inventory
);

fn smoke_ath10k_ht40_denied_secondary_selects_real_ht20_before_any_width_publication() -> TestResult
{
    for fault in 0..4 {
        let result = (|| {
            let h = harness(true, 5180)?;
            if fault == 3 {
                h.device
                    .radio
                    .try_lock()
                    .unwrap()
                    .htt
                    .wmi
                    .caps
                    .as_mut()
                    .unwrap()
                    .high_5ghz = 5180;
            } else {
                restriction(
                    h.policy.lock().as_mut().unwrap(),
                    5200,
                    if fault == 0 {
                        RegFlags::NO_IR
                    } else {
                        RegFlags::empty()
                    },
                    if fault == 1 { 20 } else { 40 },
                );
                if fault == 2 {
                    h.policy
                        .lock()
                        .as_mut()
                        .unwrap()
                        .rules
                        .last_mut()
                        .unwrap()
                        .max_power_dbm = -1;
                }
            }
            h.model(|m| {
                let f = m.data.as_mut().unwrap();
                f.ht_secondary = None;
                f.ht_sgi = true;
                f.rx_phy = Some((8, 7, 0x80));
            });
            h.join()?;
            let p = h.device.radio.try_lock().unwrap().prepared_peer().unwrap();
            if p.bandwidth_mhz != 20
                || p.center_frequency != 5180
                || h.model(|m| m.data.as_ref().unwrap().ht_inventory) != 0
            {
                return Err("denied secondary retained a wider native/request profile");
            }
            let (_, down) = packets();
            let encrypted = h.model(|m| m.data.as_mut().unwrap().downlink(&down));
            rx(&h, encrypted.clone(), 0x87, 0);
            if h.received(&down) {
                return Err("fallback20 accepted HT40 PPDU");
            }
            rx(&h, encrypted, 7, 0x80);
            if !h.received(&down) {
                return Err("rejected width consumed fallback replay PN");
            }
            Ok(())
        })();
        if let Err(e) = result {
            return TestResult::Fail(e);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht40",
    smoke_ath10k_ht40_denied_secondary_selects_real_ht20_before_any_width_publication
);

fn smoke_ath10k_ht40_response_geometry_or_basic_mcs_change_never_publishes_peer() -> TestResult {
    for fault in 0..5 {
        let result = (|| {
            let h = harness(true, 5180)?;
            h.model(|m| {
                let v = m.data.as_mut().unwrap().ht_response.as_mut().unwrap();
                match fault {
                    0 => v[31] = 0,
                    1 => v[31] = 7,
                    2 => v[30] = 40,
                    3 => v[37] = 1,
                    _ => v.extend_from_slice(&[
                        61, 22, 36, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ]),
                }
            });
            h.scan()?;
            if !matches!(
                drive(h.device.associate_for_test(h.request(), [0x73; 32])),
                Poll::Ready(Err(_))
            ) || !h.never_opened()
                || h.model(|m| m.data.as_ref().unwrap().control_phase) > 2
                || !h.model(|m| m.ce.as_ref().unwrap().retained())
            {
                return Err("HT40 response changed native geometry/mandatory MCS or opened port");
            }
            Ok(())
        })();
        if let Err(e) = result {
            return TestResult::Fail(e);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht40",
    smoke_ath10k_ht40_response_geometry_or_basic_mcs_change_never_publishes_peer
);

fn smoke_ath10k_ht40_ppdu_width_guard_mcs_and_replay_are_independent() -> TestResult {
    for (sig, guard) in [(0x87, 0x80), (0x88, 0), (8, 0)] {
        let result = (|| {
            let h = harness(true, 5180)?;
            h.join()?;
            let (_, down) = packets();
            let encrypted = h.model(|m| m.data.as_mut().unwrap().downlink(&down));
            rx(&h, encrypted.clone(), sig, guard);
            if h.received(&down) {
                return Err("unnegotiated HT40 RX PHY escaped");
            }
            rx(&h, encrypted.clone(), 0x87, 0);
            if !h.received(&down) {
                return Err("bad HT40 PHY consumed native CCMP PN");
            }
            rx(&h, encrypted, 7, 0x80);
            if h.received(&down) {
                return Err("replayed HT20 fallback inherited fresh PN");
            }
            let next = h.model(|m| m.data.as_mut().unwrap().downlink(&down));
            rx(&h, next, 7, 0x80);
            if !h.received(&down) {
                return Err("advertised SGI20 RX was incorrectly suppressed by LGI40 TX");
            }
            Ok(())
        })();
        if let Err(e) = result {
            return TestResult::Fail(e);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht40",
    smoke_ath10k_ht40_ppdu_width_guard_mcs_and_replay_are_independent
);

fn smoke_ath10k_ht40_each_native_prepare_cancel_keeps_dma_and_no_carrier() -> TestResult {
    for stage in 0..5 {
        let result = (|| {
            let h = harness(true, 5180)?;
            h.scan()?;
            h.model(|m| {
                m.station = Some(StationFixture::new());
                if stage == 4 {
                    m.data.as_mut().unwrap().ht_inventory_hold = true;
                } else {
                    m.station.as_mut().unwrap().stall = Some(stage);
                }
            });
            if !drive(h.device.associate_for_test(h.request(), [0x73; 32])).is_pending()
                || !h.never_opened()
                || !h.model(|m| m.ce.as_ref().unwrap().retained())
            {
                return Err("cancelled native HT40 preparation lost DMA/opened carrier");
            }
            h.pump();
            if !h.never_opened()
                || !matches!(
                    drive(h.device.associate_for_test(h.request(), [0x73; 32])),
                    Poll::Ready(Err(_))
                )
            {
                return Err("cancelled HT40 owner was reconstructed");
            }
            Ok(())
        })();
        if let Err(e) = result {
            return TestResult::Fail(e);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht40",
    smoke_ath10k_ht40_each_native_prepare_cancel_keeps_dma_and_no_carrier
);

fn smoke_ath10k_ht40_current_secondary_is_rechecked_inside_native_wait() -> TestResult {
    for inventory in [false, true] {
        let result = (|| {
            let h = harness(true, 5180)?;
            h.scan()?;
            h.model(|m| {
                m.station = Some(StationFixture::new());
                if inventory {
                    m.data.as_mut().unwrap().ht_inventory_hold = true;
                } else {
                    m.station.as_mut().unwrap().stall = Some(2);
                }
            });
            let mut f = Box::pin(h.device.associate_for_test(h.request(), [0x73; 32]));
            let mut cx = Context::from_waker(Waker::noop());
            for _ in 0..4096 {
                if f.as_mut().poll(&mut cx).is_ready() {
                    return Err("HT40 enabling wait did not reach held native publication");
                }
            }
            restriction(h.policy.lock().as_mut().unwrap(), 5200, RegFlags::NO_IR, 40);
            if !matches!(f.as_mut().poll(&mut cx), Poll::Ready(Err(_))) {
                return Err("native HT40 wait ignored changed secondary grant");
            }
            drop(f);
            h.pump();
            if !h.never_opened() || !h.model(|m| m.ce.as_ref().unwrap().retained()) {
                return Err("HT40 grant revocation reopened owner or freed native DMA");
            }
            Ok(())
        })();
        if let Err(e) = result {
            return TestResult::Fail(e);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht40",
    smoke_ath10k_ht40_current_secondary_is_rechecked_inside_native_wait
);

fn smoke_ath10k_ht40_final_receive_allocation_and_stack_callback_require_secondary() -> TestResult {
    use crate::ath10k::interface::ReceivePoint;
    for point in [
        ReceivePoint::AfterFrameAllocation,
        ReceivePoint::BeforeCallbackAdmission,
    ] {
        let result = (|| {
            let h = harness(true, 5180)?;
            h.join()?;
            let original = h.policy.lock().clone().ok_or("HT40 original policy")?;
            let permission = h
                .device
                .radio
                .try_lock()
                .unwrap()
                .data_permission()
                .ok_or("HT40 retained permission")?;
            let fired = Arc::new(AtomicBool::new(false));
            let flag = fired.clone();
            let authorized = Arc::new(AtomicBool::new(false));
            let authorization = authorized.clone();
            let policy = h.policy.clone();
            h.device.set_receive_hook_for_test(move |p| {
                if p == point && !flag.swap(true, Ordering::AcqRel) {
                    let mut current = policy.lock();
                    authorization.store(
                        permission.check(current.as_ref().unwrap()).is_ok(),
                        Ordering::Release,
                    );
                    restriction(current.as_mut().unwrap(), 5200, RegFlags::NO_IR, 40);
                }
            });
            let (_, down) = packets();
            let before = narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets;
            let bytes = h.model(|m| m.data.as_mut().unwrap().downlink(&down));
            rx(&h, bytes, 0x87, 0);
            if !fired.load(Ordering::Acquire)
                || !authorized.load(Ordering::Acquire)
                || !h.closed()
                || narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != before
            {
                return Err("HT40 receive publication retained only a primary20 grant");
            }
            // IPC publication precedes the independent callback boundary.
            // Exactly that prior-authorized copy is valid; no callback or
            // subsequent copy can inherit its earlier occupied40 grant.
            if h.received(&down) != (point == ReceivePoint::BeforeCallbackAdmission)
                || h.received(&down)
            {
                return Err("HT40 final publication did not preserve exact IPC/callback ordering");
            }
            *h.policy.lock() = Some(original);
            let later = h.model(|m| m.data.as_mut().unwrap().downlink(&down));
            rx(&h, later, 0x87, 0);
            let (up, _) = packets();
            if !h.closed()
                || h.received(&down)
                || h.device.enqueue(&up, narf_net::TxMeta::plain()).is_ok()
                || narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != before
            {
                return Err("restored HT40 policy revived a terminal publication owner");
            }
            Ok(())
        })();
        if let Err(e) = result {
            return TestResult::Fail(e);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht40",
    smoke_ath10k_ht40_final_receive_allocation_and_stack_callback_require_secondary
);

fn smoke_ath10k_ht40_changed_ap_operation_closes_without_relabel_or_replay() -> TestResult {
    let result = (|| {
        let h = harness(true, 5180)?;
        h.join()?;
        h.model(|m| {
            m.data.as_mut().unwrap().ht_offer.as_mut().unwrap()[31] = 0;
            let beacon = m.data.as_ref().unwrap().beacon();
            management_frame(m, beacon);
        });
        h.pump();
        if !h.closed() || !h.model(|m| m.ce.as_ref().unwrap().retained()) {
            return Err("AP HT Operation changed without a retained native channel transition");
        }
        Ok(())
    })();
    result.map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/ht40",
    smoke_ath10k_ht40_changed_ap_operation_closes_without_relabel_or_replay
);
