//! Native replay retains logical channel ownership across the physical reset.
use super::*;

struct Sibling {
    dev: Arc<TNetdev>,
    name: &'static str,
    shared: Arc<TShared>,
}
impl Drop for Sibling {
    fn drop(&mut self) {
        narf_net::iface::unregister(self.name);
        self.shared.release_vdev(1);
    }
}
fn sibling_ap(u: &Up) -> Result<Sibling, &'static str> {
    ensure!(
        u.shared.reserve_vdev() == Some(1) && u.shared.assign_vdev_iftype(1, 3),
        "native sibling AP slot"
    );
    let (mut caps, reg) = {
        let rt = run(u.shared.lock());
        (
            rt.device_caps().map_err(|_| "sibling caps")?,
            rt.core.reg_info.clone(),
        )
    };
    let own = [2, 3, 7, 0x12, 0x34, 0x57];
    caps.mac_addr = own;
    let mac = Mac::new(
        Port(u.shared.clone(), 1),
        Port(u.shared.clone(), 1),
        caps,
        MacConfig::wcn6855().with_vdev(1),
        reg.as_deref(),
    );
    let name = narf_net::iface::reserve_name("wlan%d");
    let (nd, _consumer) = Ath11kNetdev::new_on_vdev(
        name,
        u.shared.clone(),
        mac,
        own,
        Sinks {
            rx: rx_sink,
            link: link_sink,
            admin: admin_sink,
            disconnected: disc_sink,
            mlme_tx: mlme_tx_sink,
            control_port: control_port_sink,
        },
        1,
        3,
    );
    let dev = Arc::new(nd);
    narf_net::iface::register(name, own, test_send);
    dev.request_admin(true);
    run(dev.service_once());
    // A minimal legacy5GHz AP template, independently authored.
    let mut head = vec![0x80, 0, 0, 0];
    head.extend_from_slice(&[255; 6]);
    head.extend_from_slice(&own);
    head.extend_from_slice(&own);
    head.extend_from_slice(&[0; 10]);
    head.extend_from_slice(&100u16.to_le_bytes());
    head.extend_from_slice(&1u16.to_le_bytes());
    head.extend_from_slice(&[
        0, 3, b'a', b'p', b'1', 1, 8, 0x8c, 18, 0x98, 36, 0xb0, 72, 96, 108,
    ]);
    dev.start_ap(narf_wireless::ApConfig {
        ssid: b"ap1".to_vec(),
        beacon_head: head,
        beacon_tail: vec![],
        probe_resp: None,
        beacon_interval: 100,
        dtim_period: 1,
        frequency_mhz: 5180,
        channel_width: 0,
        center_freq1_mhz: None,
        center_freq2_mhz: None,
        hidden_ssid: 0,
        privacy: false,
        mbssid: None,
        mbssid_elems: vec![],
        ema_rnr_elems: vec![],
        fils_discovery: None,
        unsol_bcast_probe_resp: None,
        ftm_responder: None,
        twt_responder: false,
        he_obss_pd: None,
        he_bss_color: None,
    })
    .map_err(|_| "native AP request")?;
    let (_, error, _, _) = latched(|| run(dev.service_once()));
    ensure!(
        error == 0 && dev.link_up() && run(dev.mac.lock()).ap_active(),
        "native sibling AP start"
    );
    Ok(Sibling {
        dev,
        name,
        shared: u.shared.clone(),
    })
}
fn reservations(u: &Up) -> R {
    ensure!(
        u.shared.operating_channels() == [2437, 5180, 0, 0],
        "recovery lost a retained STA/AP channel claim"
    );
    ensure!(
        u.shared.reserve_operating_channel(2, 2462).is_none(),
        "third channel stole a recovering vdev's claim"
    );
    Ok(())
}
fn reset_root(u: &Up) -> R {
    crash(u, FwNotice::Reset(MhiNotify::SysError));
    run(u.shared.irq.wait(10));
    run(u.shared.lock()).service();
    let notice = run(u.shared.take_fw_notice()).ok_or("missing native reset notice")?;
    ensure!(
        run(u.netdev.recover_one(notice, false)),
        "native coordinator STA replay"
    );
    Ok(())
}
fn replay_ap(u: &Up, s: &Sibling) -> bool {
    let (caps, reg) = {
        let rt = run(u.shared.lock());
        (rt.device_caps().unwrap(), rt.core.reg_info.clone())
    };
    run(s.dev.rebuild_after_radio_recovery(caps, reg))
}
fn smoke_ath11k_native_recovery_retains_shared_sta_ap_channel_claims() -> TestResult {
    check(|| {
        let u = up(wpa2_cfg())?;
        connect(&u)?;
        let s = sibling_ap(&u)?;
        reservations(&u)?;
        reset_root(&u)?;
        reservations(&u)?;
        ensure!(replay_ap(&u, &s), "native sibling AP replay");
        reservations(&u)?;
        run(u.shared.reconfig_complete());
        ensure!(
            u.netdev.link_up() && s.dev.link_up(),
            "native STA/AP replay preserved carrier"
        );
        ensure!(
            run(u.netdev.mac.lock())
                .vif()
                .and_then(|v| v.chanctx)
                .is_some_and(|c| c.freq == 2437),
            "actual STA channel replay"
        );
        ensure!(
            run(s.dev.mac.lock())
                .vif()
                .and_then(|v| v.chanctx)
                .is_some_and(|c| c.freq == 5180),
            "actual AP channel replay"
        );
        Ok(())
    })
}
fn smoke_ath11k_native_recovery_failed_sibling_releases_only_closed_claim() -> TestResult {
    check(|| {
        let u = up(wpa2_cfg())?;
        connect(&u)?;
        let s = sibling_ap(&u)?;
        reset_root(&u)?;
        reservations(&u)?;
        u.dev
            .st
            .borrow_mut()
            .world
            .cfg
            .as_mut()
            .unwrap()
            .vdev_start_status = Some(3);
        ensure!(
            !replay_ap(&u, &s),
            "firmware start failure did not fail sibling replay"
        );
        ensure!(
            u.shared.is_dead()
                && !s.dev.link_up()
                && u.shared.operating_channels() == [2437, 0, 0, 0],
            "failed sibling erased live STA claim or kept closed AP claim"
        );
        Ok(())
    })
}
fn smoke_ath11k_native_recovery_cancelled_sibling_keeps_its_claim_and_dma() -> TestResult {
    check(|| {
        let u = up(wpa2_cfg())?;
        connect(&u)?;
        let s = sibling_ap(&u)?;
        reset_root(&u)?;
        reservations(&u)?;
        let (caps, reg, before) = {
            let mut rt = run(u.shared.lock());
            let eid = rt.core.wmi_ep.unwrap().eid as usize;
            rt.core.htc.endpoints[eid].tx_credits = 1;
            (
                rt.device_caps().unwrap(),
                rt.core.reg_info.clone(),
                rt.core.stats.wmi_cmds,
            )
        };
        u.dev.pause_wait.store(true, Ordering::Release);
        {
            let mut replay = pin!(s.dev.rebuild_after_radio_recovery(caps, reg));
            ensure!(
                replay
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending(),
                "native replay did not suspend after publication"
            );
        }
        reservations(&u)?;
        ensure!(
            run(u.shared.lock()).core.stats.wmi_cmds == before + 1,
            "cancel fixture did not publish exactly one real CE/WMI command"
        );
        u.dev.pause_wait.store(false, Ordering::Release);
        u.dev.step();
        ensure!(
            u.shared.operating_channels() == [2437, 5180, 0, 0],
            "late native credit freed cancelled replay claim"
        );
        ensure!(
            // Linux's four ACs map to hardware queues [0,1,2,0]; queue3
            // is not a producer for this profile. Check every actual AC,
            // including BK's shared queue, rather than an unused queue.
            [0, 1, 2, 0].into_iter().all(|q| run(u.shared.lock())
                .vdev(1)
                .unwrap()
                .txq
                .stop_reasons(q)
                & (1 << super::super::txq::reason::DRIVER)
                != 0),
            "cancelled sibling reopened native data queues"
        );
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k/recovery",
    smoke_ath11k_native_recovery_retains_shared_sta_ap_channel_claims
);
kernel_test_in!(
    "drivers/wireless/ath11k/recovery",
    smoke_ath11k_native_recovery_failed_sibling_releases_only_closed_claim
);
kernel_test_in!(
    "drivers/wireless/ath11k/recovery",
    smoke_ath11k_native_recovery_cancelled_sibling_keeps_its_claim_and_dma
);
