//! Physical CE/HTC/WMI statistics transactions; no mock of the send path.
use super::*;

fn response(pdev: u32, half_dbm: u32) -> Vec<u8> {
    let mut header = [0; 44];
    header[0] = 4;
    header[4] = 1;
    header[28..32].copy_from_slice(&pdev.to_le_bytes());
    let mut record = [0; 228];
    record[24..28].copy_from_slice(&half_dbm.to_le_bytes());
    wmi_event(0x1d004, &[tlv(0x46, &header), tlv(17, &record)])
}
fn rig(rev: HwRev) -> Result<Up, &'static str> {
    let u = up_down_caps_for_rev(wpa2_cfg(), |_| {}, rev)?;
    ensure!(
        narf_net::iface::set_link_state(u.name, true),
        "statistics fixture IFF_UP"
    );
    pump(&u, 1);
    connect(&u)?;
    Ok(u)
}
fn count(u: &Up) -> usize {
    u.dev
        .st
        .borrow()
        .wmi
        .iter()
        .filter(|c| c.cmd_id == 0x16001)
        .count()
}

fn smoke_ath11k_int_firmware_power_native_readback() -> TestResult {
    check(|| {
        for rev in [HwRev::Wcn6855Hw21, HwRev::Qca6390Hw20] {
            let u = rig(rev)?;
            let pdev = run(u.netdev.mac.lock())
                .tx_power_query_pdev()
                .ok_or("missing live power query context")?;
            // Unsolicited target statistics cannot overwrite the fallback.
            u.dev
                .st
                .borrow_mut()
                .world
                .events
                .push_back(response(pdev, 80));
            pump(&u, 2);
            ensure!(
                u.shared.firmware_tx_power_dbm().is_none(),
                "unsolicited pdev stats ignored"
            );
            let fallback = run(u.netdev.mac.lock()).tx_power_dbm();
            ensure!(
                u.netdev.tx_power_dbm() == fallback,
                "GET_INTERFACE retains bss_conf fallback"
            );
            // Multiple readers/vdev workers share one untagged transaction.
            for _ in 0..3 {
                u.shared.request_tx_power();
            }
            pump(&u, 2);
            ensure!(count(&u) == 1, "one coalesced physical PDEV request");
            let command = u
                .dev
                .st
                .borrow()
                .wmi
                .iter()
                .find(|c| c.cmd_id == 0x16001)
                .cloned()
                .ok_or("missing actual CE/HTC command")?;
            let mut literal = vec![
                20, 0, 0x8f, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            literal.extend_from_slice(&pdev.to_le_bytes());
            ensure!(
                command.buf == literal,
                "native command uses exact pdev/no peer/no vdev wire"
            );
            u.dev
                .st
                .borrow_mut()
                .world
                .events
                .push_back(response(pdev + 1, 80));
            let mut short = response(pdev, 23);
            short.pop();
            u.dev.st.borrow_mut().world.events.push_back(short);
            pump(&u, 2);
            ensure!(
                u.shared.firmware_tx_power_dbm().is_none(),
                "foreign/truncated firmware stats do not publish"
            );
            run(u.shared.refresh_tx_power(pdev)).map_err(|_| "coalesced query")?;
            pump(&u, 1);
            ensure!(
                count(&u) == 1,
                "malformed receipts do not recycle transaction"
            );
            u.dev
                .st
                .borrow_mut()
                .world
                .events
                .push_back(response(pdev, 23));
            pump(&u, 2);
            ensure!(
                u.shared.firmware_tx_power_dbm() == Some(11),
                "actual firmware half-dBm minimum cached"
            );
            ensure!(
                u.netdev.tx_power_dbm() == Some(11),
                "GET_INTERFACE reads actual target power"
            );
            u.shared.restore_operating_channel(0, 2417);
            ensure!(
                u.shared.firmware_tx_power_dbm().is_none(),
                "channel change invalidates physical telemetry"
            );
        }
        Ok(())
    })
}

fn smoke_ath11k_int_power_query_cancelled_lock_retains_owner() -> TestResult {
    check(|| {
        let u = rig(HwRev::Wcn6855Hw21)?;
        let pdev = run(u.netdev.mac.lock())
            .tx_power_query_pdev()
            .ok_or("power context")?;
        let held = run(u.shared.lock());
        {
            let mut future = pin!(u.shared.refresh_tx_power(pdev));
            ensure!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending(),
                "statistics waits for real runtime lock"
            );
        }
        drop(held);
        run(u.shared.refresh_tx_power(pdev)).map_err(|_| "cancelled query coalescing")?;
        pump(&u, 1);
        ensure!(
            count(&u) == 0,
            "cancelled reservation cannot publish a successor"
        );
        // Even a foreign/unsolicited response cannot ACK an unpublished
        // cancelled request. A completed reset is its only recovery route.
        u.dev
            .st
            .borrow_mut()
            .world
            .events
            .push_back(response(pdev, 23));
        pump(&u, 2);
        ensure!(
            u.shared.firmware_tx_power_dbm().is_none(),
            "unpublished cancellation not acknowledged by unsolicited event"
        );
        Ok(())
    })
}

fn smoke_ath11k_int_power_query_native_failure_and_late_receipt() -> TestResult {
    check(|| {
        let u = rig(HwRev::Wcn6855Hw21)?;
        let pdev = run(u.netdev.mac.lock())
            .tx_power_query_pdev()
            .ok_or("power context")?;
        let endpoint = {
            let mut rt = run(u.shared.lock());
            rt.core.wmi_ep.take()
        };
        ensure!(
            run(u.shared.refresh_tx_power(pdev)).is_err(),
            "missing native WMI endpoint fails send"
        );
        run(u.shared.lock()).core.wmi_ep = endpoint;
        run(u.shared.refresh_tx_power(pdev)).map_err(|_| "known unpublished failure retry")?;
        pump(&u, 1);
        ensure!(
            count(&u) == 1,
            "failed native send releases only unpublished reservation"
        );
        NOW.fetch_add(1001, Ordering::Relaxed);
        run(u.shared.refresh_tx_power(pdev)).map_err(|_| "expired transaction remains owned")?;
        pump(&u, 1);
        ensure!(count(&u) == 1, "timeout cannot reuse untagged request");
        u.dev
            .st
            .borrow_mut()
            .world
            .events
            .push_back(response(pdev, 23));
        pump(&u, 2);
        ensure!(
            u.shared.firmware_tx_power_dbm().is_none(),
            "late native response not published as fresh power"
        );
        run(u.shared.refresh_tx_power(pdev))
            .map_err(|_| "actual terminal response permits next query")?;
        pump(&u, 1);
        ensure!(
            count(&u) == 2,
            "actual terminal receipt retires expired request"
        );
        run(u.shared.lock()).pre_reconfigure_recovery();
        ensure!(
            u.shared.firmware_tx_power_dbm().is_none(),
            "crash closes target power cache"
        );
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k/integration",
    smoke_ath11k_int_firmware_power_native_readback
);
kernel_test_in!(
    "drivers/wireless/ath11k/integration",
    smoke_ath11k_int_power_query_cancelled_lock_retains_owner
);
kernel_test_in!(
    "drivers/wireless/ath11k/integration",
    smoke_ath11k_int_power_query_native_failure_and_late_receipt
);

fn smoke_ath11k_int_power_query_old_waiter_cannot_post_after_reset() -> TestResult {
    check(|| {
        let u = rig(HwRev::Wcn6855Hw21)?;
        let pdev = run(u.netdev.mac.lock())
            .tx_power_query_pdev()
            .ok_or("power context")?;
        let held = run(u.shared.lock());
        let mut old = pin!(u.shared.refresh_tx_power(pdev));
        ensure!(
            old.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "old stats query waits for native runtime lock"
        );
        drop(held);
        // Actual firmware/CE/HTC/DP reset and MAC reconstruction while the
        // old task is unscheduled, then a real successor native query.
        crash(&u, FwNotice::Reset(MhiNotify::SysError));
        let (_, error, _, _) = latched(|| pump(&u, 1));
        ensure!(
            error == 0 && !u.shared.is_dead(),
            "physical reset/native MAC reconstruction"
        );
        ensure!(
            run(u.netdev.mac.lock()).tx_power_query_pdev() == Some(pdev),
            "successor query uses actually restored MAC channel context"
        );
        run(u.shared.refresh_tx_power(pdev)).map_err(|_| "successor stats request")?;
        pump(&u, 1);
        ensure!(
            count(&u) == 1,
            "successor owns sole post-reset native query"
        );
        ensure!(
            old.as_mut().poll(&mut Context::from_waker(Waker::noop()))
                == Poll::Ready(Err(runtime::ESHUTDOWN)),
            "old task cannot post into successor runtime"
        );
        pump(&u, 1);
        ensure!(count(&u) == 1, "old task never publishes duplicate request");
        u.dev
            .st
            .borrow_mut()
            .world
            .events
            .push_back(response(pdev, 23));
        pump(&u, 2);
        ensure!(
            u.shared.firmware_tx_power_dbm() == Some(11),
            "old task preserves successor response ownership"
        );
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k/integration",
    smoke_ath11k_int_power_query_old_waiter_cannot_post_after_reset
);
