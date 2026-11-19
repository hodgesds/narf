//! Real retained C21 firmware/reserved-DMA/CCMP/Device, private RF model only.
use super::*;
use crate::rtw88::{firmware_transport::runtime_lps, qualification, runtime_ps_scope::KIND};
use narf_net::native_emission::Lifetime;

fn setup(
    protected: bool,
    features: u32,
) -> Result<(Harness, Cap<FirmwareBlob, Read>, Lifetime), &'static str> {
    let h = Harness::with_features(protected, features)?;
    h.join()?;
    let request = {
        let mut retained = complete(h.lifecycle.retained.lock())?;
        retained
            .as_mut()
            .unwrap()
            .lps_request()
            .map_err(|_| "LPS source request")?
    };
    let cap = Cap::bootstrap();
    let mut bytes = vec![0; 128];
    bytes[..4].copy_from_slice(b"N21Z");
    bytes[4..8].copy_from_slice(&[1, 0, 128, 0]);
    bytes[8..12].copy_from_slice(&128u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&[0xec, 0x10, 0x21, 0xc8]);
    bytes[16..48].copy_from_slice(&request.identity);
    bytes[48..54].copy_from_slice(&request.mac);
    bytes[54..57].copy_from_slice(&[b'Z', 1, 1]);
    h.port
        .qualify(
            &KIND,
            qualification::Source::Verified {
                bytes,
                signer: Some([0x2a; 32]),
                cap,
            },
        )
        .map_err(|_| "LPS source qualification")?;
    h.port.0.lock().ps_model = true;
    let snapshot = narf_net::iface::lookup(h.device.name()).ok_or("LPS original netdev")?;
    let host = narf_net::iface::OpenStopEvent::observe(&snapshot)
        .and_then(|up| up.native_identity())
        .ok_or("LPS original UP")?;
    Ok((h, cap, host))
}
fn sleep(h: &Harness, host: Lifetime) -> Result<(), runtime_lps::Error> {
    let mut retained = complete(h.lifecycle.retained.lock()).unwrap();
    complete(retained.as_mut().unwrap().lps_window(host, 5)).unwrap()
}

fn smoke_rtw8821ce_lps_real_reserved_dma_open_wpa2_wake_then_kernel_dhcp() -> TestResult {
    for protected in [false, true] {
        for features in [0, 3] {
            let (h, _, host) = match setup(protected, features) {
                Ok(h) => h,
                Err(e) => return TestResult::Fail(e),
            };
            let (bells, acquires) = {
                let m = h.port.0.lock();
                let acquires = m.ring.lock().acquires;
                (m.doorbells, acquires)
            };
            if sleep(&h, host).is_err() {
                return TestResult::Fail("actual reserved-DMA LPS/wake failed");
            }
            {
                let m = h.port.0.lock();
                if m.doorbells != bells + 1
                    || m.ring.lock().acquires != acquires + 1
                    || !m.mailboxes.ends_with(&[
                        [0, 0, 1, 3, 2, 0, 0, 0],
                        [0x20, 1, 0x21, 1, 0, 0, 0, 0],
                        [0x20, 0, 0, 1, 0, 12, 0, 0],
                    ])
                    || m.bytes[0x604] & 0x80 != 0
                    || m.bytes[0x383] & 16 != 0
                    || m.ring.lock().bytes.iter().any(|b| *b != 0)
                {
                    return TestResult::Fail(
                        "LPS skipped real completion/disarm or source H2C/TCR receipts",
                    );
                }
            }
            let plan = h.peer.lock().plan;
            match narf_net::dhcp::dhcp_acquire(h.device.name(), 0) {
                Ok(lease) if plan.matches_lease(&lease) => (),
                _ => return TestResult::Fail("confirmed LPS wake lost real native DHCP path"),
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/ps",
    smoke_rtw8821ce_lps_real_reserved_dma_open_wpa2_wake_then_kernel_dhcp
);

fn smoke_rtw8821ce_lps_stale_rfon_and_mailbox_consumption_cannot_awaken_data() -> TestResult {
    for stuck_tcr in [false, true] {
        let (h, _, host) = match setup(true, 3) {
            Ok(h) => h,
            Err(e) => return TestResult::Fail(e),
        };
        {
            let mut m = h.port.0.lock();
            m.packet_model.receive(&[0x32, 7], true, false);
            m.ps_suppress_rfon = !stuck_tcr;
            m.ps_wake_stuck = stuck_tcr;
        }
        if sleep(&h, host) != Err(runtime_lps::Error::Native(Error::Timeout)) || !h.device.closed()
        {
            return TestResult::Fail(
                "old RFON/consumed mailbox/fresh RFON without real TCR clear reopened DATA",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/ps",
    smoke_rtw8821ce_lps_stale_rfon_and_mailbox_consumption_cannot_awaken_data
);

fn smoke_rtw8821ce_lps_firmware_awake_with_wrong_actual_power_stays_closed() -> TestResult {
    let (h, _, host) = match setup(true, 3) {
        Ok(h) => h,
        Err(e) => return TestResult::Fail(e),
    };
    h.port.0.lock().ps_corrupt_power = true;
    if sleep(&h, host) != Err(runtime_lps::Error::Native(Error::Prerequisite)) || !h.device.closed()
    {
        return TestResult::Fail(
            "firmware wake receipt substituted for actual RF/TXAGC restoration",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/ps",
    smoke_rtw8821ce_lps_firmware_awake_with_wrong_actual_power_stays_closed
);

fn smoke_rtw8821ce_lps_source_or_original_up_loss_after_own_denies_doorbell() -> TestResult {
    for down_up in [false, true] {
        let (h, cap, host) = match setup(true, 3) {
            Ok(h) => h,
            Err(e) => return TestResult::Fail(e),
        };
        let (ring, bells) = {
            let m = h.port.0.lock();
            (m.ring.clone(), m.doorbells)
        };
        let name = narf_net::iface::lookup(h.device.name()).unwrap().name;
        h.port.0.lock().before_publication = Some(Arc::new(move || {
            let owned = word(&ring.lock().bytes, 0) & 0x8000_0000 != 0;
            if owned {
                if down_up {
                    narf_net::iface::set_link_state(&name, false);
                    narf_net::iface::set_link_state(&name, true);
                } else {
                    cap.revoke();
                }
            }
        }));
        if sleep(&h, host).is_ok() || !h.device.closed() || h.port.0.lock().doorbells != bells {
            return TestResult::Fail("revoked original PS/UP published native beacon doorbell");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/ps",
    smoke_rtw8821ce_lps_source_or_original_up_loss_after_own_denies_doorbell
);

fn smoke_rtw8821ce_lps_cancelled_native_page_retains_uncertain_dma_and_closes() -> TestResult {
    let (h, _, host) = match setup(true, 3) {
        Ok(h) => h,
        Err(e) => return TestResult::Fail(e),
    };
    let before = h.drops.load(Ordering::Acquire);
    {
        let mut m = h.port.0.lock();
        m.stall = true;
        m.hold_delay = Some(10);
    }
    {
        let mut retained = complete(h.lifecycle.retained.lock()).unwrap();
        let mut future = Box::pin(retained.as_mut().unwrap().lps_window(host, 5));
        if future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return TestResult::Fail("native page did not wait actual BCN_VALID");
        }
        drop(future);
    }
    if !h.device.closed() || h.drops.load(Ordering::Acquire) != before {
        return TestResult::Fail("cancelled LPS reopened station or freed live beacon DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/ps",
    smoke_rtw8821ce_lps_cancelled_native_page_retains_uncertain_dma_and_closes
);

fn smoke_rtw8821ce_lps_private_ccmp_rx_is_preserved_until_confirmed_awake() -> TestResult {
    let (h, _, host) = match setup(true, 3) {
        Ok(h) => h,
        Err(e) => return TestResult::Fail(e),
    };
    let plan = h.peer.lock().plan;
    let bytes = narf_wifi_fixtures::udp_ipv4(
        OWN,
        AP,
        plan.server_ip,
        plan.lease_ip,
        7,
        49152,
        b"native-CCMP-during-LPS",
    );
    h.port.0.lock().hold_delay = Some(5000);
    {
        let mut retained = complete(h.lifecycle.retained.lock()).unwrap();
        let mut future = Box::pin(retained.as_mut().unwrap().lps_window(host, 5));
        if future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return TestResult::Fail("LPS window did not reach actual nondeep wait");
        }
        let frame = match h.peer.lock().downlink(&bytes) {
            Ok(f) => f,
            Err(e) => return TestResult::Fail(e),
        };
        {
            let mut m = h.port.0.lock();
            m.packet_model.receive(&frame, false, false);
            m.hold_delay = None;
        }
        if !h.received().is_empty() || complete(future).unwrap().is_err() {
            return TestResult::Fail("LPS published RX before wake or lost real wake receipt");
        }
    }
    h.pump();
    if !h.received().contains(&bytes) {
        return TestResult::Fail("confirmed wake discarded or rekeyed original CCMP RX");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/ps",
    smoke_rtw8821ce_lps_private_ccmp_rx_is_preserved_until_confirmed_awake
);

/// Input/source loss after HMEBOX_EXT staging and before the low-word write
/// that publishes LPS entry: the staged extension is not a command.
fn smoke_rtw8821ce_lps_input_or_source_loss_after_ext_staging_leaves_entry_unissued() -> TestResult
{
    let enter = [0x20, 1, 0x21, 1, 0, 0, 0, 0];
    for revoke in [false, true] {
        let (h, cap, host) = match setup(true, 3) {
            Ok(h) => h,
            Err(e) => return TestResult::Fail(e),
        };
        let port = h.port.clone();
        h.port.0.lock().ps_gap = Some((
            [0x20, 1],
            Arc::new(move || {
                if revoke {
                    cap.revoke();
                } else {
                    // AP deauthentication arrives in the staging gap.
                    let mut deauth = vec![0xc0, 0, 0, 0];
                    deauth.extend_from_slice(&OWN);
                    deauth.extend_from_slice(&AP);
                    deauth.extend_from_slice(&AP);
                    deauth.extend_from_slice(&[0x10, 0, 7, 0]);
                    port.0.lock().packet_model.receive(&deauth, false, false);
                }
            }),
        ));
        if sleep(&h, host).is_ok() || !h.device.closed() {
            return TestResult::Fail("LPS entry survived peer/source loss in the H2C gap");
        }
        let m = h.port.0.lock();
        if m.ps_gap.is_some()
            || !m.ps_staged.contains(&enter)
            || m.mailboxes.contains(&enter)
            || m.bytes[0x604] & 0x80 != 0
        {
            return TestResult::Fail("extended-only LPS staging published or retried entry");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/ps",
    smoke_rtw8821ce_lps_input_or_source_loss_after_ext_staging_leaves_entry_unissued
);

/// Benign protected DATA in the wake-command gap: the command stays unissued,
/// the RX prefix is retained privately, then the wake H2C is staged again and
/// published exactly once.
fn smoke_rtw8821ce_lps_rx_in_wake_h2c_gap_retries_unissued_once_and_keeps_data() -> TestResult {
    let wake = [0x20, 0, 0, 1, 0, 0x0c, 0, 0];
    let (h, _, host) = match setup(true, 3) {
        Ok(h) => h,
        Err(e) => return TestResult::Fail(e),
    };
    let plan = h.peer.lock().plan;
    let bytes = narf_wifi_fixtures::udp_ipv4(
        OWN,
        AP,
        plan.server_ip,
        plan.lease_ip,
        7,
        49152,
        b"native-CCMP-in-wake-gap",
    );
    let frame = match h.peer.lock().downlink(&bytes) {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let port = h.port.clone();
    h.port.0.lock().ps_gap = Some((
        [0x20, 0],
        Arc::new(move || port.0.lock().packet_model.receive(&frame, false, false)),
    ));
    if sleep(&h, host).is_err() {
        return TestResult::Fail("unissued wake H2C was not retried after RX retirement");
    }
    {
        let m = h.port.0.lock();
        // Station bring-up already published one ACTIVE power-mode H2C;
        // count only the wake published after this window's LPS entry.
        let entry = m.mailboxes.iter().rposition(|w| w[..2] == [0x20, 1]);
        if m.ps_staged.iter().filter(|w| **w == wake).count() != 2
            || entry.is_none_or(|at| m.mailboxes[at..].iter().filter(|w| **w == wake).count() != 1)
        {
            return TestResult::Fail("wake H2C published twice or without restaging");
        }
    }
    h.pump();
    if !h.received().contains(&bytes) {
        return TestResult::Fail("gap RX lost across unissued wake retry");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/ps",
    smoke_rtw8821ce_lps_rx_in_wake_h2c_gap_retries_unissued_once_and_keeps_data
);
