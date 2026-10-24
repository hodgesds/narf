//! Actual retained Device → native CE/HTT/Supplicant → kernel DHCP/IP.
//! Only the firmware/AP and physical DMA register interface are models.
use super::*;
use crate::ath10k::interface::Device;
use alloc::{string::String, sync::Arc};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};
use narf_net::Interface;
use narf_wireless::{AssociateRequest, ScanRequest, SecurityConfig};
type ModelDevice = Device<RadioModel>;
static ACTIVE_TEST: IrqSafeSpinLock<Option<Arc<ModelDevice>>> = IrqSafeSpinLock::new(None);
fn send(bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let device = ACTIVE_TEST.lock().clone().ok_or(())?;
    device.enqueue(bytes, meta)
}
fn drain() -> bool {
    let device = ACTIVE_TEST.lock().clone();
    device.is_some_and(|device| device.drain())
}
struct Harness {
    device: Arc<ModelDevice>,
    policy: Arc<IrqSafeSpinLock<Option<narf_wireless::reg::RegulatoryDomain>>>,
    name: String,
    secured: bool,
}
impl Harness {
    fn new(version: u32, dialect: Dialect, secured: bool) -> Self {
        let mut radio = radio_boot_features(
            version,
            dialect,
            (1 << 10) | (1 << 2) | if dialect == Dialect::Tlv { 1 << 18 } else { 0 },
        );
        assert!(matches!(
            drive(radio.start(&[2412, 5180])),
            Poll::Ready(Ok(_))
        ));
        let m = &mut radio.htt.wmi.htc.transport;
        let mut fixture = Fixture::new(secured);
        fixture.automatic = true;
        m.data = Some(fixture);
        let hardware = if dialect == Dialect::Tlv {
            HwRev::Qca6174
        } else if dialect == Dialect::TenFour {
            HwRev::Qca9984
        } else {
            HwRev::Qca988x
        };
        m.ce = Some(crate::ath10k::boot::CeFixture::new(hardware));
        let name = narf_net::iface::register("wlan%d", OWN, send);
        let policy = Arc::new(IrqSafeSpinLock::new(Some(station_tests::policy())));
        let current = policy.clone();
        let device = Arc::new(Device::for_test(
            &name,
            OWN,
            Arc::new(Mutex::new(radio)),
            move || current.lock().clone(),
        ));
        *ACTIVE_TEST.lock() = Some(device.clone());
        narf_net::iface::set_link_state(&name, false);
        narf_net::iface::set_link_metadata(&name, false, None, None);
        narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
        narf_net::iface::install_rx_drain(drain);
        Self {
            device,
            policy,
            name,
            secured,
        }
    }
    fn request(&self) -> AssociateRequest {
        AssociateRequest {
            bssid: AP,
            ssid: b"narf".to_vec(),
            frequency_mhz: 2412,
            channel: 1,
            security: if self.secured {
                SecurityConfig::Wpa2 { psk: PMK }
            } else {
                SecurityConfig::Open
            },
            ie: Vec::new(),
        }
    }
    fn scan(&self) -> Result<(), &'static str> {
        let Poll::Ready(Ok(bss)) = drive(self.device.scan(ScanRequest {
            ssids: vec![b"narf".to_vec()],
            frequencies_mhz: vec![2412],
            channels: vec![1],
            active: false,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: None,
            duration_mandatory: false,
            extra_ies: Vec::new(),
        })) else {
            return Err("retained Device native scan failed");
        };
        if bss.len() != 1 || bss[0].bssid != AP || bss[0].frequency_mhz != 2412 {
            return Err("retained Device scan identity");
        }
        Ok(())
    }
    fn join(&self) -> Result<(), &'static str> {
        self.scan()?;
        if !matches!(
            drive(self.device.associate_for_test(self.request(), [0x73; 32])),
            Poll::Ready(Ok(()))
        ) {
            return Err("native Device management/early-M1/RSNA failed");
        }
        if !self.device.link_up()
            || narf_net::iface::lookup(&self.name)
                .is_none_or(|i| !i.carrier || i.carrier_up_count != 1 || i.carrier_down_count != 0)
        {
            return Err("real Device carrier did not follow exact authorization");
        }
        Ok(())
    }
    fn pump(&self) {
        for _ in 0..12 {
            self.device.drain();
        }
    }
    fn model<R>(&self, operation: impl FnOnce(&mut RadioModel) -> R) -> R {
        let mut r = self.device.radio.try_lock().unwrap();
        operation(&mut r.htt.wmi.htc.transport)
    }
    fn closed(&self) -> bool {
        !self.device.link_up()
            && narf_net::iface::lookup(&self.name).is_some_and(|i| {
                !i.carrier && !i.link_up && i.carrier_up_count == 1 && i.carrier_down_count == 1
            })
    }
    fn received(&self, expected: &[u8]) -> bool {
        let mut rx = self.device.rx_ring().lock();
        let Some(rx) = rx.as_mut() else {
            return false;
        };
        for _ in 0..narf_net::RX_RING_N {
            let Ok(Some(frame)) = rx.try_recv() else {
                break;
            };
            if frame.payload() == expected {
                return true;
            }
        }
        false
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        *ACTIVE_TEST.lock() = None;
        narf_net::iface::set_link_state(&self.name, false);
        narf_net::iface::set_link_metadata(&self.name, false, None, None);
        narf_net::iface::unregister(&self.name);
    }
}
fn composition(version: u32, dialect: Dialect, secured: bool) -> Result<(), &'static str> {
    let h = Harness::new(version, dialect, secured);
    let (uplink, downlink) = packets();
    if narf_net::dhcp::acquire(&h.name, 0).is_ok()
        || h.device.enqueue(&uplink, narf_net::TxMeta::plain()).is_ok()
    {
        return Err("DHCP/data escaped preauthorization carrier");
    }
    h.join()?;
    let lease = narf_net::dhcp::dhcp_acquire(&h.name, 0)
        .map_err(|_| "actual kernel DHCP through CE/HTT failed")?;
    if !network().matches_lease(&lease)
        || !h.model(|m| {
            let f = m.data.as_ref().unwrap();
            let seen = f.server.observations();
            seen.discovers == 1 && seen.requests == 1 && f.ap.phase() == ApPhase::Authorized
        })
    {
        return Err("native AP DHCP conversation or exact lease terms");
    }
    narf_net::iface::send_on(&h.name, &uplink).map_err(|_| "native netdev uplink enqueue")?;
    h.pump();
    if !h.model(|m| m.data.as_ref().unwrap().uplink.contains(&uplink)) {
        return Err("native HTT/AP IP uplink changed");
    }
    let before = narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets;
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        let frame = f.downlink(&downlink);
        f.queue.push_back(frame);
    });
    h.pump();
    if !h.received(&downlink)
        || narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets <= before
    {
        return Err("native IP downlink did not reach both Narf-Ring and kernel stack intact");
    }
    h.model(|m| teardown_tests::arm_data_disconnect(m, false));
    if !matches!(drive(h.device.disassociate()), Poll::Ready(Ok(()))) {
        return Err("native Device terminal peer/vdev disconnect failed");
    }
    h.pump();
    if !h.closed()
        || narf_net::iface::send_on(&h.name, &uplink).is_ok()
        || !h.model(|m| {
            m.ce.as_ref().unwrap().retained() && m.inner.storage.as_ref().unwrap().tx.pending() == 0
        })
    {
        return Err("native disconnect reused DMA or left carrier/data open");
    }
    let name = h.name.clone();
    drop(h);
    if narf_net::ipv4::lookup_binding(&name).is_some() {
        return Err("removed ath10k netdev retained DHCP binding");
    }
    Ok(())
}
fn smoke_ath10k_native_device_open_wpa2_dhcp_and_bidirectional_ip() -> TestResult {
    for (version, dialect) in [
        (1, Dialect::Main),
        (2, Dialect::TenOne),
        (3, Dialect::TenTwo),
        (4, Dialect::Tlv),
        (5, Dialect::TenTwoFour),
        (6, Dialect::TenFour),
    ] {
        for secured in [false, true] {
            if let Err(e) = composition(version, dialect, secured) {
                return TestResult::Fail(e);
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/station",
    smoke_ath10k_native_device_open_wpa2_dhcp_and_bidirectional_ip
);
fn occupancy(htt_first: bool) -> Result<(), &'static str> {
    let h = Harness::new(4, Dialect::Tlv, true);
    h.join()?;
    let (uplink, downlink) = packets();
    h.model(|m| {
        m.ce.as_mut().unwrap().hold_source(true);
        m.data.as_mut().unwrap().hold_data = true;
    });
    narf_net::iface::send_on(&h.name, &uplink).map_err(|_| "held native submit")?;
    h.pump();
    let (bounce, sent) = h.model(|m| {
        (
            m.ce.as_ref().unwrap().source_bytes(4),
            m.ce.as_ref().unwrap().sent,
        )
    });
    if !h.model(|m| {
        m.inner.storage.as_ref().unwrap().tx.pending() == 1
            && !m.ce.as_mut().unwrap().source_ready(4).unwrap()
    }) {
        return Err("fixture did not retain real CE/HTT owners");
    }
    narf_net::iface::send_on(&h.name, &uplink).map_err(|_| "queued second native submit")?;
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        let frame = f.downlink(&downlink);
        f.queue.push_back(frame);
    });
    h.pump();
    if !h.received(&downlink)
        || !h.device.link_up()
        || !h.model(|m| {
            m.ce.as_ref().unwrap().sent == sent
                && m.ce.as_ref().unwrap().source_bytes(4) == bounce
                && m.inner.storage.as_ref().unwrap().tx.pending() == 1
        })
    {
        return Err("pending CE bounce overwritten, forged HTT completion or RX stalled");
    }
    if htt_first {
        h.model(|m| {
            let id = m.data.as_mut().unwrap().held.pop_front().unwrap();
            complete(m, id, 0);
        });
        h.pump();
        if !h.model(|m| {
            m.ce.as_ref().unwrap().sent == sent
                && m.ce.as_ref().unwrap().source_bytes(4) == bounce
                && !m.ce.as_mut().unwrap().source_ready(4).unwrap()
                && m.inner.storage.as_ref().unwrap().tx.pending() == 0
        }) {
            return Err("HTT receipt reused CE bounce before its terminal source index");
        }
    }
    h.model(|m| m.ce.as_mut().unwrap().hold_source(false));
    if !h.model(|m| m.ce.as_mut().unwrap().source_ready(4).unwrap()) {
        return Err("fixture release did not publish actual terminal CE source index");
    }
    if !htt_first {
        h.pump();
        if !h.model(|m| {
            m.ce.as_ref().unwrap().sent == sent
                && m.inner.storage.as_ref().unwrap().tx.pending() == 1
        }) {
            return Err("CE receipt substituted for actual HTT completion");
        }
        h.model(|m| {
            let id = m.data.as_mut().unwrap().held.pop_front().unwrap();
            complete(m, id, 0);
        });
    }
    h.pump();
    if !h.model(|m| {
        m.ce.as_ref().unwrap().sent == sent + 1
            && m.inner.storage.as_ref().unwrap().tx.pending() == 1
            && m.data.as_ref().unwrap().held.len() == 1
            && m.data.as_ref().unwrap().uplink == [uplink.clone(), uplink]
    }) {
        return Err("terminal HTT ID did not unlock exactly queued frame");
    }
    Ok(())
}
fn smoke_ath10k_ce_bounce_busy_preserves_rx_and_exact_htt_ownership() -> TestResult {
    for htt_first in [false, true] {
        if let Err(e) = occupancy(htt_first) {
            return TestResult::Fail(e);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/station",
    smoke_ath10k_ce_bounce_busy_preserves_rx_and_exact_htt_ownership
);
fn smoke_ath10k_device_held_m4_cancellation_cannot_raise_carrier() -> TestResult {
    let h = Harness::new(4, Dialect::Tlv, true);
    if let Err(e) = h.scan() {
        return TestResult::Fail(e);
    }
    h.model(|m| m.data.as_mut().unwrap().hold_m4 = true);
    {
        let mut future = core::pin::pin!(h.device.associate_for_test(h.request(), [0x73; 32]));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..48 {
            if future.as_mut().poll(&mut cx).is_ready() {
                return TestResult::Fail("native held M4 raised carrier");
            }
        }
    }
    h.pump();
    if h.device.link_up()
        || narf_net::dhcp::acquire(&h.name, 0).is_ok()
        || !h.model(|m| {
            m.data.as_ref().unwrap().ap.phase() == ApPhase::Authorized
                && m.data.as_ref().unwrap().held.len() == 1
                && m.inner.storage.as_ref().unwrap().tx.pending() == 1
                && m.ce.as_ref().unwrap().retained()
        })
    {
        return TestResult::Fail("cancelled actual M4 lost DMA or opened DHCP/carrier");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/station",
    smoke_ath10k_device_held_m4_cancellation_cannot_raise_carrier
);
fn smoke_ath10k_device_connection_loss_and_failed_disconnect_stay_terminal() -> TestResult {
    for fail in [false, true] {
        let h = Harness::new(4, Dialect::Tlv, true);
        if let Err(e) = h.join() {
            return TestResult::Fail(e);
        }
        let (uplink, _) = packets();
        h.model(|m| m.data.as_mut().unwrap().hold_data = true);
        if narf_net::iface::send_on(&h.name, &uplink).is_err() {
            return TestResult::Fail("negative data enqueue");
        }
        h.pump();
        if fail {
            h.model(|m| teardown_tests::arm_data_disconnect(m, true));
            if !matches!(drive(h.device.disassociate()), Poll::Ready(Err(_))) {
                return TestResult::Fail("failed native disconnect accepted");
            }
        } else {
            h.device.radio.try_lock().unwrap().expire_data_for_test();
            h.pump();
        }
        if !h.closed()
            || narf_net::iface::send_on(&h.name, &uplink).is_ok()
            || !h.model(|m| {
                m.inner.storage.as_ref().unwrap().tx.pending() == 1
                    && m.ce.as_ref().unwrap().retained()
            })
            || !matches!(
                drive(h.device.associate_for_test(h.request(), [0x73; 32])),
                Poll::Ready(Err(_))
            )
        {
            return TestResult::Fail(
                "lost/failed native station reopened or reclaimed uncertain DMA",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/station",
    smoke_ath10k_device_connection_loss_and_failed_disconnect_stay_terminal
);

fn smoke_ath10k_host_close_worker_interleave_preserves_native_teardown() -> TestResult {
    let h = Harness::new(4, Dialect::Tlv, false);
    if let Err(e) = h.join() {
        return TestResult::Fail(e);
    }
    h.device.close_before_lock_for_test();
    h.pump();
    if h.device.radio.try_lock().unwrap().prepared_peer().is_none() {
        return TestResult::Fail(
            "host-close worker poisoned radio before teardown could acquire it",
        );
    }
    h.model(|m| teardown_tests::arm_data_disconnect(m, false));
    if !matches!(drive(h.device.disassociate()), Poll::Ready(Ok(())))
        || !h.closed()
        || !h.model(|m| teardown_tests::data_disconnect_completed(m))
    {
        return TestResult::Fail("worker interleave prevented real DOWN/DELETE/STOP correlation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/station",
    smoke_ath10k_host_close_worker_interleave_preserves_native_teardown
);

fn rekey_and_offloads() -> Result<(), &'static str> {
    let h = Harness::new(4, Dialect::Tlv, true);
    h.join()?;
    let (uplink, _) = packets();
    let before = h.model(|m| m.data.as_ref().unwrap().uplink.len());
    for meta in [
        narf_net::TxMeta::with_csum(narf_net::L4CsumKind::Udp),
        narf_net::TxMeta::with_tso(1200),
        narf_net::TxMeta {
            vlan_tag: Some(7),
            ..narf_net::TxMeta::plain()
        },
    ] {
        if h.device.enqueue(&uplink, meta).is_ok() {
            return Err("unsupported netdev offload admitted");
        }
        let memory = narf_io::alloc_coherent(uplink.len(), narf_lib::id::DomainId::DRIVER_0)
            .map_err(|_| "offload test memory")?;
        let mut frame = narf_net::Frame::new(memory, uplink.len() as u32);
        frame.payload_mut().copy_from_slice(&uplink);
        frame.set_tx_meta(meta);
        h.device
            .tx_ring()
            .lock()
            .as_mut()
            .unwrap()
            .try_send(frame)
            .map_err(|_| "direct offload ring submit")?;
        h.pump();
    }
    if h.model(|m| m.data.as_ref().unwrap().uplink.len()) != before {
        return Err("direct frame-ring client bypassed offload admission");
    }
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        f.hold_data = true;
        let group = f.group_rekey();
        f.queue.push_back(group);
    });
    h.pump();
    if !h.device.link_up()
        || !h.model(|m| {
            m.data.as_ref().unwrap().held.len() == 1 && m.data.as_ref().unwrap().group_replies == 1
        })
    {
        return Err("native GTK reply wait lost carrier or exact terminal owner");
    }
    narf_net::iface::send_on(&h.name, &uplink).map_err(|_| "rekey queued uplink")?;
    h.pump();
    if h.model(|m| m.data.as_ref().unwrap().uplink.len()) != before
        || narf_net::iface::lookup(&h.name)
            .is_none_or(|i| !i.carrier || i.carrier_up_count != 1 || i.carrier_down_count != 0)
    {
        return Err("GTK reply wait opened data port or flapped physical carrier");
    }
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        f.hold_data = false;
        let id = f.held.pop_front().unwrap();
        complete(m, id, 0);
    });
    h.pump();
    if !h.model(|m| m.data.as_ref().unwrap().uplink.contains(&uplink)) || !h.device.link_up() {
        return Err("real GTK reply receipt did not reopen queued native data");
    }
    Ok(())
}
fn smoke_ath10k_native_rekey_keeps_carrier_and_ring_offloads_stay_closed() -> TestResult {
    match rekey_and_offloads() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/ath10k/station",
    smoke_ath10k_native_rekey_keeps_carrier_and_ring_offloads_stay_closed
);

fn smoke_ath10k_close_mid_progress_fences_native_tx_rx_and_stale_carrier() -> TestResult {
    let h = Harness::new(4, Dialect::Tlv, true);
    if let Err(e) = h.join() {
        return TestResult::Fail(e);
    }
    let (uplink, downlink) = packets();
    if narf_net::iface::send_on(&h.name, &uplink).is_err() {
        return TestResult::Fail("mid-progress native TX enqueue");
    }
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        let frame = f.downlink(&downlink);
        f.queue.push_back(frame);
        super::poll(m).unwrap();
    });
    let sent = h.model(|m| m.ce.as_ref().unwrap().sent);
    let rx = narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets;
    h.device.close_mid_progress_for_test();
    h.device.drain();
    h.device.stale_link_after_close_for_test(AP);
    if !h.closed()
        || h.received(&downlink)
        || narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != rx
        || h.model(|m| m.ce.as_ref().unwrap().sent) != sent
        || narf_net::iface::send_on(&h.name, &uplink).is_ok()
    {
        return TestResult::Fail(
            "host close raced native publication, RX dispatch or stale carrier intent",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/station",
    smoke_ath10k_close_mid_progress_fences_native_tx_rx_and_stale_carrier
);

fn smoke_ath10k_current_policy_restriction_fences_native_station_publication() -> TestResult {
    for (version, dialect) in [(1, Dialect::Main), (4, Dialect::Tlv)] {
        for restriction in 0..3 {
            let h = Harness::new(version, dialect, true);
            if let Err(e) = h.join() {
                return TestResult::Fail(e);
            }
            let (uplink, downlink) = packets();
            if narf_net::iface::send_on(&h.name, &uplink).is_err() {
                return TestResult::Fail("policy restriction host TX setup");
            }
            h.model(|m| {
                let f = m.data.as_mut().unwrap();
                let frame = f.downlink(&downlink);
                f.queue.push_back(frame);
            });
            let sent = h.model(|m| m.ce.as_ref().unwrap().sent);
            let rx = narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets;
            let mut restricted = station_tests::policy();
            match restriction {
                // This still permits channel1, but no longer permits the
                // power actually programmed by START. It cannot be silently
                // accepted without a distinct native retune/power owner.
                0 => restricted.rules[0].max_power_dbm = 16,
                1 => restricted.rules[0].freq_start_mhz = 2427,
                _ => {}
            }
            *h.policy.lock() = (restriction != 2).then_some(restricted);
            h.pump();
            if !h.closed()
                || h.received(&downlink)
                || narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != rx
                || !h.model(|m| {
                    m.ce.as_ref().unwrap().sent == sent
                        && m.inner.storage.as_ref().unwrap().tx.pending() == 0
                        && m.data.as_ref().unwrap().uplink.is_empty()
                })
                || narf_net::iface::send_on(&h.name, &uplink).is_ok()
            {
                return TestResult::Fail(
                    "restricted current policy published native TX/RX or retained carrier",
                );
            }
            *h.policy.lock() = Some(station_tests::policy());
            h.pump();
            if !h.closed() || h.model(|m| m.ce.as_ref().unwrap().sent) != sent {
                return TestResult::Fail("policy restoration reopened terminal station");
            }
        }
        let h = Harness::new(version, dialect, false);
        if let Err(e) = h.scan() {
            return TestResult::Fail(e);
        }
        let sent = h.model(|m| m.sent.len());
        let mut restricted = station_tests::policy();
        restricted.rules[0].freq_start_mhz = 2427;
        *h.policy.lock() = Some(restricted);
        if !matches!(
            drive(h.device.associate_for_test(h.request(), [0x73; 32])),
            Poll::Ready(Err(_))
        ) || h.model(|m| m.sent.len()) != sent
            || h.device.radio.try_lock().unwrap().prepared_peer().is_some()
            || h.device.link_up()
        {
            return TestResult::Fail(
                "association used policy captured before the current restriction",
            );
        }
        let h = Harness::new(version, dialect, false);
        let sent = h.model(|m| m.sent.len());
        *h.policy.lock() = None;
        if h.scan().is_ok() || h.model(|m| m.sent.len()) != sent {
            return TestResult::Fail("passive scan published without current receive policy");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/station",
    smoke_ath10k_current_policy_restriction_fences_native_station_publication
);
