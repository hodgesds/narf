//! Native RTS intent over retained CE/HTT with independent WMI literals in
//! data_tests::protection_send. No synthesized firmware parameter ACKs.
use super::*;
use radio::StationProtection as Request;
fn forty(
    secured: bool,
    version: u32,
    dialect: Dialect,
    protection: u8,
) -> Result<Harness, &'static str> {
    let h = Harness::new_on(version, dialect, secured, false, 5180, 0x8348);
    ht40_conversation_tests::enable(&h)?;
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        for ies in [&mut f.ht_offer, &mut f.ht_response] {
            // Exact HT Cap28 followed by HT Operation24; operation info2
            // is at byte32. It is not WMI's boolean PROTECTION_MODE.
            ies.as_mut().unwrap()[32] = protection;
        }
    });
    Ok(h)
}
fn smoke_ath10k_ht40_native_protection_modes_keep_forced_rts_all_six_dialects() -> TestResult {
    (|| {
        for (version, dialect) in BAND_DIALECTS {
            for mode in 0..4 {
                let h = forty(mode & 1 != 0, version, dialect, mode)?;
                h.join()?;
                let (up, down) = packets();
                narf_net::iface::send_on(&h.name, &up).map_err(|_| "RTS native uplink")?;
                h.pump();
                h.model(|m| {
                    let f = m.data.as_mut().unwrap();
                    let p = f.downlink(&down);
                    f.queue.push_back(p);
                });
                h.pump();
                if !h.received(&down)
                    || !h.model(|m| {
                        let f = m.data.as_ref().unwrap();
                        f.protection_trace.len() == 3
                            && f.uplink.contains(&up)
                            && f.protection_trace[0].1 == 0x21
                            && f.protection_trace[1].1 == 0
                            && f.protection_trace[2] == (1, 0)
                    })
                {
                    return Err(
                        "HT40 native RTS program/traffic did not match original protection mode",
                    );
                }
                let mut r = h.device.radio.try_lock().unwrap();
                if r.submitted_station_protection()
                    != Some(Request {
                        rts_threshold: Some(0),
                        cts_protection: false,
                    })
                {
                    return Err("HT40 did not retain exact submitted RTS intent");
                }
                if mode != 0 {
                    let before = r.htt.wmi.htc.transport.sent.len();
                    if !matches!(
                        drive(r.set_station_protection(Request::default(), || {
                            h.policy.lock().clone().ok_or(radio::Error::Unsupported)
                        })),
                        Poll::Ready(Err(radio::Error::Unsupported))
                    ) || r.htt.wmi.htc.transport.sent.len() != before
                        || r.station_link().is_none()
                    {
                        return Err(
                            "HT40 mixed-mode RTS floor was relaxed or poisoned retryable preflight",
                        );
                    }
                }
            }
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/protection",
    smoke_ath10k_ht40_native_protection_modes_keep_forced_rts_all_six_dialects
);

fn smoke_ath10k_protection_waits_real_old_packet_receipt_and_preserves_original_rx() -> TestResult {
    (|| {
        let h = forty(true, 4, Dialect::Tlv, 0)?;
        h.join()?;
        h.model(|m| m.data.as_mut().unwrap().hold_data = true);
        let (up, down) = packets();
        narf_net::iface::send_on(&h.name, &up).map_err(|_| "RTS drain uplink")?;
        h.pump();
        if !h.model(|m| {
            m.data.as_ref().unwrap().held.len() == 1
                && m.inner.storage.as_ref().unwrap().tx.pending() == 1
        }) {
            return Err("RTS drain fixture did not retain real old HTT payload");
        }
        let request = Request {
            rts_threshold: Some(128),
            cts_protection: true,
        };
        h.model(|m| {
            let f = m.data.as_mut().unwrap();
            f.protection_request = Some(request);
            f.protection_delay = 3;
            let p = f.downlink(&down);
            f.queue.push_back(p);
        });
        {
            let mut r = h.device.radio.try_lock().unwrap();
            if drive(r.set_station_protection(request, || {
                h.policy.lock().clone().ok_or(radio::Error::Unsupported)
            })) != Poll::Ready(Ok(request))
            {
                return Err("RTS did not drain exact native HTT receipt before parameter program");
            }
            if r.submitted_station_protection() != Some(request)
                || r.htt
                    .wmi
                    .htc
                    .transport
                    .inner
                    .storage
                    .as_ref()
                    .unwrap()
                    .tx
                    .pending()
                    != 0
            {
                return Err("RTS program lost exact intent or native terminal payload lifetime");
            }
        }
        h.pump();
        if !h.received(&down)
            || !h.model(|m| m.data.as_ref().unwrap().protection_trace.len() == 6)
            || !h.device.link_up()
        {
            return Err("RTS control consumed following original RX or closed successful owner");
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/protection",
    smoke_ath10k_protection_waits_real_old_packet_receipt_and_preserves_original_rx
);

fn smoke_ath10k_protection_each_native_command_cancel_keeps_dma_and_closed_owner() -> TestResult {
    (|| {
        for step in 0..3 {
            let h = forty(true, 4, Dialect::Tlv, 0)?;
            h.join()?;
            let request = Request {
                rts_threshold: Some(512),
                cts_protection: true,
            };
            h.model(|m| {
                let f = m.data.as_mut().unwrap();
                f.protection_request = Some(request);
                f.protection_hold = Some(step);
            });
            {
                let mut r = h.device.radio.try_lock().unwrap();
                {
                    let mut future = core::pin::pin!(r.set_station_protection(request, || h
                        .policy
                        .lock()
                        .clone()
                        .ok_or(radio::Error::Unsupported)));
                    let mut cx = Context::from_waker(Waker::noop());
                    for _ in 0..4096 {
                        if future.as_mut().poll(&mut cx).is_ready() {
                            return Err("RTS held native command unexpectedly completed");
                        }
                    }
                }
                if r.station_link().is_some()
                    || r.submitted_station_protection().is_some()
                    || r.htt
                        .wmi
                        .htc
                        .transport
                        .data
                        .as_ref()
                        .unwrap()
                        .protection_trace
                        .len()
                        != 4 + step
                    || !r.htt.wmi.htc.transport.ce.as_ref().unwrap().retained()
                {
                    return Err(
                        "cancelled RTS command lost native DMA or reopened previous program",
                    );
                }
            }
            h.pump();
            if !h.closed() {
                return Err("cancelled native RTS program retained carrier");
            }
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/protection",
    smoke_ath10k_protection_each_native_command_cancel_keeps_dma_and_closed_owner
);

fn smoke_ath10k_protection_source_or_policy_change_at_each_native_command_is_terminal() -> TestResult
{
    (|| {
        for step in 0..3 {
            for asset in 0..3 {
                let h=forty(true,4,Dialect::Tlv,0)?;
                let (source,caps)=crate::ath10k::firmware_source::fixture()?;
                h.model(|m|m.sources=Some(source));h.join()?;
                let request=Request {rts_threshold:Some(256),cts_protection:true};
                h.model(|m| {let f=m.data.as_mut().unwrap(); f.protection_request=Some(request);f.protection_change_at=step;
                    if asset<2 {f.protection_revoke=Some(caps[asset]);} else {f.protection_policy=Some(h.policy.clone());}});
                {
                    let mut r=h.device.radio.try_lock().unwrap();
                    if !matches!(drive(r.set_station_protection(request,||h.policy.lock().clone().ok_or(radio::Error::Unsupported))),Poll::Ready(Err(_)))
                        || r.station_link().is_some() || r.submitted_station_protection().is_some()
                        || r.htt.wmi.htc.transport.data.as_ref().unwrap().protection_trace.len()!=4+step {
                        return Err("native RTS program ignored exact revoked source/current occupied power");
                    }
                }
                h.pump();
                if !h.closed() {return Err("revoked RTS program retained carrier");}
            }
        }
        Ok(())
    })().map_or_else(TestResult::Fail,|()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/protection",
    smoke_ath10k_protection_source_or_policy_change_at_each_native_command_is_terminal
);

fn smoke_ath10k_protection_invalid_threshold_is_retryable_before_native_program() -> TestResult {
    (|| {
        let h = Harness::new(4, Dialect::Tlv, false);
        h.join()?;
        let mut r = h.device.radio.try_lock().unwrap();
        let before = r.htt.wmi.htc.transport.sent.len();
        if drive(r.set_station_protection(
            Request {
                rts_threshold: Some(2348),
                cts_protection: false,
            },
            || h.policy.lock().clone().ok_or(radio::Error::Unsupported),
        )) != Poll::Ready(Err(radio::Error::Unsupported))
            || r.station_link().is_none()
            || r.htt.wmi.htc.transport.sent.len() != before
        {
            return Err("invalid RTS threshold reached native program or poisoned current station");
        }
        for request in [
            Request {
                rts_threshold: Some(2347),
                cts_protection: false,
            },
            Request::default(),
        ] {
            r.htt
                .wmi
                .htc
                .transport
                .data
                .as_mut()
                .unwrap()
                .protection_request = Some(request);
            if drive(r.set_station_protection(request, || {
                h.policy.lock().clone().ok_or(radio::Error::Unsupported)
            })) != Poll::Ready(Ok(request))
            {
                return Err("valid RTS maximum/disabled native threshold encoding failed");
            }
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/protection",
    smoke_ath10k_protection_invalid_threshold_is_retryable_before_native_program
);

/// One Device worker pass: the synchronous drain, then its await point.
fn service(h: &Harness) {
    h.pump();
    let _ = drive(h.device.flush_management());
}
fn expect(h: &Harness, request: Request) {
    h.model(|m| m.data.as_mut().unwrap().protection_request = Some(request));
}
fn erp_beacon(h: &Harness, erp: Option<u8>) {
    h.model(|m| {
        let mut beacon = m.data.as_ref().unwrap().beacon();
        if let Some(value) = erp {
            beacon.extend_from_slice(&[42, 1, value]);
        }
        management_frame(m, beacon);
    });
}
fn smoke_ath10k_beacon_erp_protection_reprograms_cts_all_six_dialects() -> TestResult {
    (|| {
        for (version, dialect) in BAND_DIALECTS {
            for secured in [false, true] {
                let h = Harness::new(version, dialect, secured);
                h.join()?;
                // mac80211 ieee80211_handle_bss_capability: ERP Use_Protection
                // raises BSS_CHANGED_ERP_CTS_PROT -> ath10k_bss_info_changed.
                let on = Request {
                    rts_threshold: None,
                    cts_protection: true,
                };
                expect(&h, on);
                erp_beacon(&h, Some(0x02));
                service(&h);
                if h.closed()
                    || !h.model(|m| {
                        let t = &m.data.as_ref().unwrap().protection_trace;
                        t.len() == 3 && t[0].1 == 0x21 && t[1].1 == 1 && t[2] == (1, u32::MAX)
                    })
                    || h.device.radio.try_lock().unwrap().submitted_station_protection() != Some(on)
                {
                    return Err("beacon ERP Use_Protection did not program use_cts_prot");
                }
                // The same ERP state again is not a change.
                erp_beacon(&h, Some(0x02));
                service(&h);
                if h.model(|m| m.data.as_ref().unwrap().protection_trace.len()) != 3 {
                    return Err("unchanged ERP protection was reprogrammed");
                }
                // ERP absent: use_cts_prot falls back to false.
                expect(&h, Request::default());
                erp_beacon(&h, None);
                service(&h);
                if h.closed()
                    || !h.model(|m| {
                        let t = &m.data.as_ref().unwrap().protection_trace;
                        t.len() == 6 && t[4].1 == 0
                    })
                {
                    return Err("cleared ERP protection did not reprogram use_cts_prot");
                }
            }
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/protection",
    smoke_ath10k_beacon_erp_protection_reprograms_cts_all_six_dialects
);
