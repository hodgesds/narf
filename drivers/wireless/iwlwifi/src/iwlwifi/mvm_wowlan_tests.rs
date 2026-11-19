//! Gen2/API77 WoWLAN: an associated native station enters D3 through the
//! exact `mvm_d3` command sequence, the fixture firmware answers resume with
//! WOWLAN_INFO/WAKE_PKT/D3_END notifications, and the same publication
//! either keeps its association and counters or restarts like Linux.
use super::*;
use crate::iwlwifi::mvm_d3;

fn wake_config() -> narf_wireless::WowlanConfig {
    narf_wireless::WowlanConfig {
        disconnect: true,
        magic_packet: true,
        ..narf_wireless::WowlanConfig::default()
    }
}

/// `struct iwl_wowlan_info_notif_v1` with `reasons`, a raised TID1 PTK
/// floor, and TID0 QoS sequence `last` (firmware's last-used value).
fn info(reasons: u32, ptk_tid1: u64, last: u16) -> Vec<u8> {
    let mut b = vec![0; mvm_d3::INFO_V1_LEN];
    b[44 + 8..44 + 16].copy_from_slice(&ptk_tid1.to_le_bytes());
    b[44 + 196..44 + 200].copy_from_slice(&[0xff; 4]);
    b[580..582].copy_from_slice(&last.to_le_bytes());
    b[596..600].copy_from_slice(&reasons.to_le_bytes());
    b
}

fn resume_notifications(h: &Harness, info_body: &[u8], packet: Option<&[u8]>, reset: bool) {
    let mut actor = h.actor.lock();
    actor.inject(0xfd, 0xb, 0x8000, info_body);
    if let Some(packet) = packet {
        let mut body = (packet.len() as u32).to_le_bytes().to_vec();
        body.extend_from_slice(&[0; 4]);
        body.extend_from_slice(packet);
        actor.inject(0xfc, 0xb, 0x8000, &body);
    }
    actor.inject(0xfe, 0xb, 0x8000, &u32::from(reset).to_le_bytes());
}

fn d3_commands(h: &Harness, start: usize) -> Vec<u8> {
    h.actor.lock().commands[start..]
        .iter()
        .filter(|(g, c, _)| *g == 1 && matches!(c, 0xe0..=0xe4 | 0xd3 | 0xd4))
        .map(|(_, c, _)| *c)
        .collect()
}

fn next_sequence(h: &Harness) -> u16 {
    let state = h.device.state.try_lock().unwrap();
    state.owner.as_ref().unwrap().model_wowlan_sequence()
}

fn smoke_mvm_gen2_wowlan_magic_wake_keeps_association_and_counters() -> TestResult {
    check(|| {
        let h = Harness::new(true)?;
        if h.device.wowlan_support() != Some(mvm_d3::support()) {
            return Err("admitted API77 image did not advertise WoWLAN");
        }
        h.join()?;
        h.device
            .set_wowlan(Some(wake_config()))
            .map_err(|_| "WoWLAN configuration refused")?;
        let start = h.actor.lock().commands.len();
        let sequence = next_sequence(&h);
        run(h.device.system_suspend())??;
        // Linux order: RSC/TSC, configuration, (patterns), offload, D3 last.
        if d3_commands(&h, start) != [0xe2, 0xe1, 0xd4, 0xd3]
            || !h.device.wowlan_d3.load(Ordering::Acquire)
            || !h.device.suspended.load(Ordering::Acquire)
            || h.device.terminal.load(Ordering::Acquire)
            || h.device.link_up()
            || h.device.connected_bssid() != Some(AP)
        {
            return Err("associated suspend did not hand the station to D3");
        }
        if run(h.device.associate(h.request()))?.is_ok() {
            return Err("D3 owner accepted association");
        }
        let packet = [0xff; 102];
        resume_notifications(
            &h,
            &info(
                mvm_d3::reason::MAGIC_PACKET,
                1000,
                (sequence << 4).wrapping_sub(0x10),
            ),
            Some(&packet),
            false,
        );
        run(h.device.system_resume())??;
        let report = h.device.wowlan_wakeup().ok_or("wake report missing")?;
        if !report.magic_packet || report.disconnect || report.packet != packet {
            return Err("magic-packet wake report differs");
        }
        if h.device.suspended.load(Ordering::Acquire)
            || h.device.wowlan_d3.load(Ordering::Acquire)
            || !h.device.link_up()
            || next_sequence(&h) != sequence
        {
            return Err("kept connection did not reopen the same station");
        }
        {
            let state = h.device.state.try_lock().unwrap();
            if state.owner.as_ref().unwrap().model_pairwise_floor(1) != 1000 {
                return Err("firmware PTK RX counter was not restored");
            }
        }
        // The same RSNA keeps carrying traffic after D3.
        let lease = narf_net::dhcp::dhcp_acquire(h.device.name(), 0)
            .map_err(|_| "DHCP after WoWLAN resume")?;
        if !NETWORK.matches_lease(&lease) {
            return Err("WoWLAN resume leased wrong address");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/wowlan",
    smoke_mvm_gen2_wowlan_magic_wake_keeps_association_and_counters
);

fn smoke_mvm_gen2_wowlan_disconnect_wake_restarts_and_rejoins() -> TestResult {
    check(|| {
        let h = Harness::new(false)?;
        h.join()?;
        h.device
            .set_wowlan(Some(wake_config()))
            .map_err(|_| "WoWLAN configuration refused")?;
        run(h.device.system_suspend())??;
        // Open BSS: no RSC/TSC command is sent (`have_rsc` false).
        if !h.device.wowlan_d3.load(Ordering::Acquire) {
            return Err("open station did not enter D3");
        }
        resume_notifications(&h, &info(mvm_d3::reason::DEAUTH, 0, 0), None, false);
        run(h.device.system_resume())??;
        let report = h.device.wowlan_wakeup().ok_or("wake report missing")?;
        if !report.disconnect
            || h.device.suspended.load(Ordering::Acquire)
            || h.device.terminal.load(Ordering::Acquire)
            || h.device.link_up()
        {
            return Err("disconnect wake did not restart a disconnected station");
        }
        {
            let mut a = h.actor.lock();
            a.security.ap = ap(false)?;
            a.m1_sent = false;
            a.data_added = false;
            a.closing = false;
            a.server = DhcpServer::new(NETWORK);
        }
        h.join()?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/wowlan",
    smoke_mvm_gen2_wowlan_disconnect_wake_restarts_and_rejoins
);

fn smoke_mvm_gen2_wowlan_reset_required_or_idle_uses_ordinary_paths() -> TestResult {
    check(|| {
        // Idle with WoWLAN configured: `__iwl_mvm_suspend` returns 1 and the
        // ordinary stop runs.
        let h = Harness::new(false)?;
        h.device
            .set_wowlan(Some(wake_config()))
            .map_err(|_| "WoWLAN configuration refused")?;
        let bad = narf_wireless::WowlanConfig {
            gtk_rekey_failure: true,
            ..narf_wireless::WowlanConfig::default()
        };
        if h.device.set_wowlan(Some(bad)).is_ok() || h.device.wowlan_config() != Some(wake_config())
        {
            return Err("unadvertised trigger replaced the retained configuration");
        }
        let start = h.actor.lock().commands.len();
        run(h.device.system_suspend())??;
        if h.device.wowlan_d3.load(Ordering::Acquire) || !d3_commands(&h, start).is_empty() {
            return Err("idle station entered D3");
        }
        run(h.device.system_resume())??;
        // Associated, but firmware requires a reset at D3 end.
        h.join()?;
        run(h.device.system_suspend())??;
        resume_notifications(
            &h,
            &info(mvm_d3::reason::MAGIC_PACKET, 0, 0),
            Some(&[1; 16]),
            true,
        );
        run(h.device.system_resume())??;
        if !h.device.wowlan_wakeup().is_some_and(|r| r.magic_packet)
            || h.device.suspended.load(Ordering::Acquire)
            || h.device.link_up()
        {
            return Err("D0I3 reset-required resume kept the association");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/wowlan",
    smoke_mvm_gen2_wowlan_reset_required_or_idle_uses_ordinary_paths
);
