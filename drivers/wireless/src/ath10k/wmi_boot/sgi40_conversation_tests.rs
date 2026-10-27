//! SGI40 over the retained native service/association/CE/HTT/RSNA owner.
//! Firmware bit0800, IEEE bit0040, RC bit04 and HT-SIG GI bit7 are
//! independent source-cited facts; no production encoder generates vectors.
use super::*;
use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, Ordering};
use narf_wireless::reg::{RegFlags, RegRule};

fn secondary(f: u16) -> Result<u16, &'static str> {
    match f {
        5180 => Ok(5200),
        5200 => Ok(5180),
        _ => Err("SGI40 native primary pair"),
    }
}
pub(super) fn enable(h: &Harness) -> Result<(), &'static str> {
    let ht = h
        .device
        .radio
        .try_lock()
        .unwrap()
        .htt
        .wmi
        .caps
        .as_ref()
        .unwrap()
        .ht;
    let (sgi20, sgi40, native) = match ht {
        1 => (false, false, 0x000e),
        3 => (true, false, 0x002e),
        0x801 => (false, true, 0x004e),
        0x803 => (true, true, 0x006e),
        _ => return Err("SGI40 fixture requires actual parsed HT service capability"),
    };
    for r in &mut h.policy.lock().as_mut().unwrap().rules {
        if r.freq_start_mhz > 3000 {
            r.max_bandwidth_mhz = 40;
        }
    }
    let s = secondary(h.frequency)?;
    let mut ies = vec![45, 26, 0x6e, 0, 0x1b, 0xff];
    ies.extend_from_slice(&[0; 11]);
    ies.push(1);
    ies.extend_from_slice(&[0; 10]);
    ies.extend_from_slice(&[
        61,
        22,
        h.request().channel as u8,
        if s > h.frequency { 5 } else { 7 },
    ]);
    ies.extend_from_slice(&[0; 20]);
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        f.wmm_offer = Some(WMM_PARAMETERS.to_vec());
        f.wmm_response = Some(WMM_PARAMETERS.to_vec());
        f.ht_offer = Some(ies.clone());
        f.ht_response = Some(ies);
        f.ht_expected = true;
        f.ht_secondary = Some(s);
        f.ht_capabilities = native;
        f.ht_request_sgi = sgi20;
        f.ht_request_sgi40 = sgi40;
        f.ht_sgi = sgi20 || sgi40;
        f.rx_phy = Some((8, 0x87, if sgi40 { 0x80 } else { 0 }));
    });
    Ok(())
}
fn harness(secured: bool, ht: u32) -> Result<Harness, &'static str> {
    let h = Harness::new_on_ht(4, Dialect::Tlv, secured, false, 5180, 0x8348, Some(ht));
    enable(&h)?;
    Ok(h)
}
fn inject(h: &Harness, frame: Vec<u8>, sig: u32, gi: u32) {
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        f.rx_phy = Some((8, sig, gi));
        f.queue.push_back(frame);
    });
    h.pump();
}
fn restrict(domain: &mut narf_wireless::reg::RegulatoryDomain, flags: RegFlags, width: u32) {
    domain.rules.push(RegRule {
        freq_start_mhz: 5199,
        freq_end_mhz: 5201,
        max_bandwidth_mhz: width,
        max_power_dbm: 27,
        flags,
    });
}

fn smoke_ath10k_sgi40_native_service_bits_and_separate_band_advertisement() -> TestResult {
    (|| {
        for (version,dialect) in BAND_DIALECTS {
            for (ht,two,five) in [(0,None,None),(0x800,None,None),
                (1,Some(0x0c),Some(0x0e)),(3,Some(0x2c),Some(0x2e)),
                (0x801,Some(0x0c),Some(0x4e)),(0x803,Some(0x2c),Some(0x6e))] {
                let h=Harness::new_on_ht(version,dialect,false,false,5180,0x8348,Some(ht));
                if h.device.radio.try_lock().unwrap().htt.wmi.caps.as_ref().unwrap().ht!=ht {
                    return Err("native SERVICE_READY did not preserve exact firmware HT bits");
                }
                for (band,cap) in [(2400,two),(5000,five)] {
                    let actual=h.device.phy_capabilities(band);
                    let expected=cap.map(|first| {
                        let mut body=[0;26];body[0]=first;body[2]=24;body[3]=255;body[15]=1;body
                    });
                    if actual.as_ref().map(|p|p.ht)!=expected || actual.is_some_and(|p|p.vht.is_some()) {
                        return Err("SGI40 band advertisement inferred GI from SGI20/width/PCI or omitted actual source bit");
                    }
                }
            }
        }
        Ok(())
    })().map_or_else(TestResult::Fail,|()|TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/sgi40",
    smoke_ath10k_sgi40_native_service_bits_and_separate_band_advertisement
);

fn smoke_ath10k_sgi40_native_six_dialects_open_wpa2_dhcp_ip_ps_and_retirement() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        for primary in [5180, 5200] {
            for secured in [false, true] {
                if let Err(e) = composition_radio(
                    version,
                    dialect,
                    secured,
                    false,
                    true,
                    primary,
                    TestPhy::Sgi40,
                ) {
                    return TestResult::Fail(e);
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/sgi40",
    smoke_ath10k_sgi40_native_six_dialects_open_wpa2_dhcp_ip_ps_and_retirement
);

fn smoke_ath10k_sgi40_original_offer_response_and_local_tx_rx_gi_are_directional() -> TestResult {
    (|| {
        // firmware,scan,response, native negotiated peer_ht_caps, RC_SGI.
        // Scan omissions cannot be restored by a response; AP RX GI must
        // not revoke the separate local RX promise sent in our request.
        for (hw, scan, response, native, rate_sgi) in [
            (0x801, 0x6e, 0x6e, 0x4e, true),
            (0x803, 0x2e, 0x6e, 0x2e, true),
            (0x803, 0x6e, 0x2e, 0x2e, true),
            (0x801, 0x6e, 0x0e, 0x0e, false),
            (3, 0x6e, 0x6e, 0x2e, true),
            (1, 0x6e, 0x6e, 0x0e, false),
            (0x801, 0x2e, 0x6e, 0x0e, false),
            (0x803, 0x4e, 0x6e, 0x4e, true),
        ] {
            let h = harness(true, hw)?;
            h.model(|m| {
                let f = m.data.as_mut().unwrap();
                f.ht_offer.as_mut().unwrap()[2] = scan;
                f.ht_response.as_mut().unwrap()[2] = response;
                f.ht_capabilities = native;
                f.ht_sgi = rate_sgi;
            });
            h.join()?;
            let (up, down) = packets();
            narf_net::iface::send_on(&h.name, &up).map_err(|_| "directional SGI native TX")?;
            h.pump();
            if !h.model(|m| m.data.as_ref().unwrap().uplink.contains(&up)) {
                return Err("directional GI native PEER_ASSOC or software CCMP TX failed");
            }
            let original = h.model(|m| m.data.as_mut().unwrap().downlink(&down));
            inject(&h, original.clone(), 0x87, 0x80);
            if h.received(&down) != (hw & 0x800 != 0) || !h.device.link_up() {
                return Err("AP receive GI was mistaken for local receive GI or native source bit");
            }
            if hw & 0x800 == 0 {
                inject(&h, original, 0x87, 0);
                if !h.received(&down) {
                    return Err("unsupported SGI40 consumed native CCMP PN");
                }
            }
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/sgi40",
    smoke_ath10k_sgi40_original_offer_response_and_local_tx_rx_gi_are_directional
);

fn smoke_ath10k_sgi40_native_ppdu_gi_width_and_mcs_checks_precede_replay() -> TestResult {
    (|| {
        for (hw, bad_sig, bad_gi, good_sig, good_gi) in [
            (0x801, 7, 0x80, 0x87, 0x80), // SGI40 is independent of SGI20.
            (3, 0x87, 0x80, 7, 0x80),     // SGI20 never promotes SGI40.
            (1, 0x87, 0x80, 0x87, 0),
            (0x803, 0x88, 0x80, 0x87, 0x80), // Unsupported MCS8.
        ] {
            let h = harness(true, hw)?;
            h.join()?;
            let (_, down) = packets();
            let frame = h.model(|m| m.data.as_mut().unwrap().downlink(&down));
            inject(&h, frame.clone(), bad_sig, bad_gi);
            if h.received(&down) || !h.device.link_up() {
                return Err("invalid native GI/MCS reached or poisoned current data owner");
            }
            inject(&h, frame.clone(), good_sig, good_gi);
            if !h.received(&down) {
                return Err("native GI/MCS denial consumed encrypted replay PN");
            }
            inject(&h, frame, good_sig, good_gi);
            if h.received(&down) {
                return Err("SGI40 enabled ordinary CCMP replay");
            }
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/sgi40",
    smoke_ath10k_sgi40_native_ppdu_gi_width_and_mcs_checks_precede_replay
);

fn smoke_ath10k_sgi40_native_ba_first_ppdu_proof_reorders_before_pn_and_expires_on_last(
) -> TestResult {
    (|| {
        let h = harness(true, 0x801)?;
        h.join()?;
        h.device.radio.try_lock().unwrap().receive_time_for_test(0);
        h.model(|m| {
            m.inner
                .inner
                .rx
                .push_back((m.inner.receive_pipe, header(1, &[5, 8, 0x80, 0x70])))
        });
        h.pump();
        if h.device.radio.try_lock().unwrap().receive_ba_for_test(0) != Some((1800, 8, 0, None)) {
            return Err("SGI40 actual sparse-peer/TID native ADDBA absent");
        }
        let (_, down) = packets();
        let packet = |sn: u16| {
            let mut frame = h.model(|m| m.data.as_mut().unwrap().downlink(&down));
            // The independent AP assigns the original SN; IEEE CCMP AAD
            // masks sequence-number bits, as in the existing BA vectors.
            frame[22..24].copy_from_slice(&(sn << 4).to_le_bytes());
            frame
        };
        let first = packet(10);
        let second = packet(11);
        let third = packet(12);
        h.model(|m| {
            let f = m.data.as_mut().unwrap();
            for (frame, descriptor) in [
                (first, (1, 8, 0x87, 0x80)),
                (third, (0, 0xff, 0x88, 0x80)),
                (second, (2, 0xff, 0x88, 0x80)),
            ] {
                f.queue.push_back(frame);
                f.rx_descriptors.push_back(descriptor);
            }
        });
        h.pump();
        if !h.received(&down)
            || !h.received(&down)
            || !h.received(&down)
            || h.received(&down)
            || h.device.radio.try_lock().unwrap().receive_ba_for_test(0)
                != Some((1800, 8, 0, Some(13)))
        {
            return Err(
                "SGI40 FIRST proof did not retain one native PPDU or reorder before CCMP PN",
            );
        }
        let retry = packet(13);
        let orphan = packet(14);
        h.model(|m| {
            let f = m.data.as_mut().unwrap();
            // New FIRST promises unsupported SGI20 on SGI40-only hardware.
            // Its LAST must not inherit the previous PPDU's SGI40 proof.
            f.queue.push_back(retry.clone());
            f.rx_descriptors.push_back((1, 8, 7, 0x80));
            f.queue.push_back(orphan);
            f.rx_descriptors.push_back((2, 0xff, 0x87, 0x80));
        });
        h.pump();
        if h.received(&down)
            || h.device.radio.try_lock().unwrap().receive_ba_for_test(0)
                != Some((1800, 8, 0, Some(13)))
        {
            return Err("SGI40 LAST leaked cached PHY proof into a rejected successor PPDU");
        }
        inject(&h, retry, 0x87, 0x80);
        if !h.received(&down) || !h.device.link_up() {
            return Err("rejected native BA GI proof consumed the same encrypted PN or sequence");
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/sgi40",
    smoke_ath10k_sgi40_native_ba_first_ppdu_proof_reorders_before_pn_and_expires_on_last
);

fn smoke_ath10k_sgi40_real_ht20_fallback_never_advertises_or_programs_sgi40() -> TestResult {
    (|| {
        for hw in [0x801, 0x803] {
            for policy in [false, true] {
                let h = harness(true, hw)?;
                if policy {
                    restrict(h.policy.lock().as_mut().unwrap(), RegFlags::empty(), 20);
                }
                h.model(|m| {
                    let f = m.data.as_mut().unwrap();
                    if !policy {
                        for ie in [&mut f.ht_offer, &mut f.ht_response] {
                            let ie = ie.as_mut().unwrap();
                            ie[2] = 0x2c;
                            ie[31] = 0;
                        }
                    }
                    f.ht_secondary = None;
                    f.ht_capabilities = if hw == 0x801 { 0x0c } else { 0x2c };
                    f.ht_sgi = hw != 0x801;
                    f.rx_phy = Some((8, 7, if hw == 0x801 { 0 } else { 0x80 }));
                });
                h.join()?;
                if h.device
                    .radio
                    .try_lock()
                    .unwrap()
                    .prepared_peer()
                    .is_none_or(|p| p.bandwidth_mhz != 20 || p.center_frequency != 5180)
                    || !h.model(|m| m.data.as_ref().unwrap().ht_inventory == 0)
                {
                    return Err("SGI40 capability bypassed genuine local20/native20 fallback");
                }
                let (_, down) = packets();
                let original = h.model(|m| m.data.as_mut().unwrap().downlink(&down));
                inject(&h, original.clone(), 0x87, 0x80);
                if h.received(&down) {
                    return Err("fallback20 inherited SGI40 RX promise");
                }
                inject(&h, original, 7, if hw == 0x801 { 0 } else { 0x80 });
                if !h.received(&down) {
                    return Err("SGI40 source bit granted SGI20 or poisoned fallback replay");
                }
            }
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/sgi40",
    smoke_ath10k_sgi40_real_ht20_fallback_never_advertises_or_programs_sgi40
);

fn smoke_ath10k_sgi40_native_prepare_wmm_m4_cancellation_retains_dma_and_no_port() -> TestResult {
    (|| {
        for stage in 0..7 {
            let h = harness(true, 0x803)?;
            h.scan()?;
            h.model(|m| {
                m.station = Some(StationFixture::new());
                match stage {
                    0..=3 => m.station.as_mut().unwrap().stall = Some(stage),
                    4 => m.data.as_mut().unwrap().ht_inventory_hold = true,
                    5 => m.data.as_mut().unwrap().wmm_hold = true,
                    _ => m.data.as_mut().unwrap().hold_m4 = true,
                }
            });
            if !drive(h.device.associate_for_test(h.request(), [0x73; 32])).is_pending()
                || !h.never_opened()
                || !h.model(|m| {
                    m.ce.as_ref().unwrap().retained()
                        && (stage != 6 || m.inner.storage.as_ref().unwrap().tx.pending() == 1)
                })
            {
                return Err(
                    "cancelled native SGI40 enabling step lost DMA or fabricated controlled port",
                );
            }
            h.pump();
            if !h.never_opened()
                || !matches!(
                    drive(h.device.associate_for_test(h.request(), [0x73; 32])),
                    Poll::Ready(Err(_))
                )
            {
                return Err("cancelled native SGI40 owner was reconstructed");
            }
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/sgi40",
    smoke_ath10k_sgi40_native_prepare_wmm_m4_cancellation_retains_dma_and_no_port
);

fn smoke_ath10k_sgi40_held_native_enable_rechecks_exact_sources_and_secondary_power() -> TestResult
{
    (|| {
        for change in 0..3 {
            for m4 in [false, true] {
                let h = harness(true, 0x803)?;
                let original = h.policy.lock().clone().ok_or("SGI40 current policy")?;
                let (source, caps) = crate::ath10k::firmware_source::fixture()?;
                h.model(|m| {
                    m.sources = Some(source);
                    let f = m.data.as_mut().unwrap();
                    if m4 {
                        f.hold_m4 = true;
                    } else {
                        f.wmm_hold = true;
                    }
                });
                h.scan()?;
                let mut future = Box::pin(h.device.associate_for_test(h.request(), [0x73; 32]));
                if !drive(future.as_mut()).is_pending() {
                    return Err("SGI40 source/power held enabling step absent");
                }
                if change < 2 {
                    caps[change].revoke();
                } else {
                    restrict(h.policy.lock().as_mut().unwrap(), RegFlags::NO_IR, 40);
                }
                if !matches!(drive(future.as_mut()), Poll::Ready(Err(_))) {
                    return Err(
                        "SGI40 native wait ignored current executable/BDF or occupied40 power",
                    );
                }
                drop(future);
                *h.policy.lock() = Some(original);
                let (fresh, _) = crate::ath10k::firmware_source::fixture()?;
                fresh.check().map_err(|_| "replacement SGI source")?;
                h.pump();
                let before = h.model(|m| m.sent.len());
                if !h.never_opened()
                    || !matches!(
                        drive(h.device.associate_for_test(h.request(), [0x73; 32])),
                        Poll::Ready(Err(_))
                    )
                    || !h.model(|m| {
                        m.sent.len() == before
                            && m.ce.as_ref().unwrap().retained()
                            && (!m4 || m.inner.storage.as_ref().unwrap().tx.pending() == 1)
                    })
                {
                    return Err(
                        "replacement policy/source revived native SGI40 enabling DMA owner",
                    );
                }
            }
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/sgi40",
    smoke_ath10k_sgi40_held_native_enable_rechecks_exact_sources_and_secondary_power
);

fn smoke_ath10k_sgi40_final_rx_ipc_and_callback_require_current_source_and_full_width() -> TestResult
{
    use crate::ath10k::interface::ReceivePoint;
    (|| {
        for change in 0..3 {
            for point in [
                ReceivePoint::AfterFrameAllocation,
                ReceivePoint::BeforeCallbackAdmission,
            ] {
                let h = harness(true, 0x803)?;
                let (source, caps) = crate::ath10k::firmware_source::fixture()?;
                h.model(|m| m.sources = Some(source));
                h.join()?;
                let permission = h
                    .device
                    .radio
                    .try_lock()
                    .unwrap()
                    .data_permission()
                    .ok_or("SGI40 current receive permission")?;
                let original = h
                    .policy
                    .lock()
                    .clone()
                    .ok_or("SGI40 original receive policy")?;
                let fired = Arc::new(AtomicBool::new(false));
                let flag = fired.clone();
                let authorized = Arc::new(AtomicBool::new(false));
                let authority = authorized.clone();
                let policy = h.policy.clone();
                h.device.set_receive_hook_for_test(move |at| {
                    if at == point && !flag.swap(true, Ordering::AcqRel) {
                        authority.store(
                            caps.iter()
                                .all(|c| c.invoke(narf_capabilities::NoopOp).is_ok())
                                && permission.check(policy.lock().as_ref().unwrap()).is_ok(),
                            Ordering::Release,
                        );
                        if change < 2 {
                            caps[change].revoke();
                        } else {
                            restrict(policy.lock().as_mut().unwrap(), RegFlags::NO_IR, 40);
                        }
                    }
                });
                let (_, down) = packets();
                let before = narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets;
                let frame = h.model(|m| m.data.as_mut().unwrap().downlink(&down));
                inject(&h, frame, 0x87, 0x80);
                if !fired.load(Ordering::Acquire)
                    || !authorized.load(Ordering::Acquire)
                    || !h.closed()
                    || narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != before
                {
                    return Err(
                        "SGI40 final publication used stale source or only a primary20 grant",
                    );
                }
                if h.received(&down) != (point == ReceivePoint::BeforeCallbackAdmission)
                    || h.received(&down)
                {
                    return Err(
                        "SGI40 revocation lost exact prior-authorized IPC/callback ordering",
                    );
                }
                *h.policy.lock() = Some(original);
                let (fresh, _) = crate::ath10k::firmware_source::fixture()?;
                fresh.check().map_err(|_| "fresh SGI40 receive source")?;
                let later = h.model(|m| m.data.as_mut().unwrap().downlink(&down));
                inject(&h, later, 0x87, 0x80);
                let (up, _) = packets();
                if !h.closed()
                    || h.received(&down)
                    || h.device.enqueue(&up, narf_net::TxMeta::plain()).is_ok()
                    || narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != before
                {
                    return Err("source/power restoration revived terminal SGI40 receive owner");
                }
            }
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/sgi40",
    smoke_ath10k_sgi40_final_rx_ipc_and_callback_require_current_source_and_full_width
);
