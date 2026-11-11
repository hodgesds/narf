//! Composed native-WiFi decap conversation (Linux's default `rawmode=0
//! cryptmode=0` on QCA6174 TLV firmware without `RAW_MODE_SUPPORT`) over
//! the actual CE/HTT/WMI/netdev path. The model firmware takes native-WiFi
//! TX MSDUs (no QoS Control; it rebuilds QoS from the descriptor TID and
//! encrypts with the key `WMI_VDEV_INSTALL_KEY` programmed, at its own PN),
//! and hands decryptable data RX up as native-WiFi MSDUs with the original
//! header and CCMP header in `rx_hdr_status`; the FakeAp still checks every
//! uplink MPDU with its own PTK and replay counter. Unexecuted until the
//! coordinated native run.
use super::*;
use narf_wireless::{WowlanConfig, WowlanPattern};

const GTK: [u8; 16] = [0x5a; 16];

fn harness(wow: bool) -> Harness {
    harness_with(wow, false)
}
fn harness_with(wow: bool, nlo: bool) -> Harness {
    let h = Harness::new_on_firmware(
        4,
        Dialect::Tlv,
        true,
        false,
        2412,
        0x64,
        NativeFirmware {
            ht: None,
            radio: RadioSource {
                hardware: HwRev::Qca6174,
                rf_chains: 2,
                vht: None,
            },
            all_inventory: false,
            // No RAW_MODE_SUPPORT (bit 10): WMI management TX by reference
            // and, optionally, WOWLAN (QCA6174 hw3.0 firmware-4/-6).
            features: (1 << 2) | (1 << 18) | if wow { 1 << 6 } else { 0 },
            htt: (3, 1),
            hardware_keys: true,
            nlo,
        },
    );
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        f.native_wifi = true;
        f.hw = Some(Box::new(HwKeyCache::default()));
    });
    h
}
fn hw<R>(h: &Harness, operation: impl FnOnce(&HwKeyCache) -> R) -> R {
    h.model(|m| operation(m.data.as_ref().unwrap().hw.as_ref().unwrap()))
}
fn native<R>(h: &Harness, operation: impl FnOnce(&Fixture) -> R) -> R {
    h.model(|m| operation(m.data.as_ref().unwrap()))
}
fn deliver(h: &Harness, frame: Vec<u8>) {
    h.model(|m| m.data.as_mut().unwrap().queue.push_back(frame));
    h.pump();
}
/// A broadcast DATA MPDU from the AP under group key `key_id`.
fn group_frame(key: &[u8; 16], key_id: u8, pn: u64, payload: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let n = network();
    let ethernet = udp_ipv4(
        [0xff; 6],
        AP,
        n.server_ip,
        [10, 77, 0, 255],
        7,
        49153,
        payload,
    );
    let mut frame = vec![8, 0x42, 0, 0];
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&[0, 0]);
    let mut body = vec![0xaa, 0xaa, 3, 0, 0, 0];
    body.extend_from_slice(&ethernet[12..]);
    let wire =
        narf_wireless::ccmp::protect(&Ccm, &frame, key, pn, key_id, 0, false, &mut body).unwrap();
    frame.extend_from_slice(&wire);
    (frame, ethernet)
}

fn conversation() -> Result<(), &'static str> {
    let h = harness(false);
    h.join()?;
    h.pump();
    // The 4-way handshake ran over native-WiFi EAPOL (M2/M4 plaintext with
    // NO_ENCRYPT), then PTK and GTK were programmed and confirmed.
    let tk = h.model(|m| m.data.as_ref().unwrap().ap.pairwise_tk().unwrap());
    if hw(&h, |c| c.installs != 2 || c.key(true, 0) != Some(tk)) {
        return Err("PTK/GTK not programmed under native WiFi");
    }
    if native(&h, |f| f.native_tx) < 2 {
        return Err("EAPOL replies did not leave as native-WiFi MSDUs");
    }
    // TX: native-WiFi MSDU without CCMP header; the firmware rebuilds the
    // MPDU, encrypts at its own PN and the AP opens it with its PTK.
    let (up, down) = packets();
    let sent = native(&h, |f| f.native_tx);
    narf_net::iface::send_on(&h.name, &up).map_err(|_| "native-WiFi uplink")?;
    h.pump();
    if !h.model(|m| m.data.as_ref().unwrap().uplink.contains(&up))
        || native(&h, |f| f.native_tx) != sent + 1
        || hw(&h, |c| c.hardware_tx) == 0
    {
        return Err("uplink was not a firmware-encrypted native-WiFi MSDU");
    }
    // RX: a decrypted native-WiFi MSDU is rebuilt with its CCMP header for
    // the host PN check; the replayed MSDU is dropped.
    let frame = h.model(|m| m.data.as_mut().unwrap().downlink(&down));
    let received = native(&h, |f| f.native_rx);
    deliver(&h, frame.clone());
    if !h.received(&down) || native(&h, |f| f.native_rx) != received + 1 {
        return Err("decrypted native-WiFi MSDU did not reach the netdev");
    }
    deliver(&h, frame);
    if h.received(&down) {
        return Err("replayed native-WiFi MSDU escaped the host PN check");
    }
    // Group rekey: message 1 arrives decrypted under the PTK; the reply
    // leaves Protected and plaintext for the firmware's PTK (no software
    // crypto exists in this decap), and its delivery installs the GTK.
    let sent = native(&h, |f| f.native_tx);
    let frame = h.model(|m| {
        let f = m.data.as_mut().unwrap();
        f.group_replay = 3;
        f.group_rekey_with(2, GTK)
    });
    deliver(&h, frame);
    if native(&h, |f| f.native_tx) != sent + 1
        || hw(&h, |c| c.installs != 3 || c.key(false, 2) != Some(GTK))
    {
        return Err("group reply not firmware-encrypted or GTK not programmed");
    }
    let (frame, ethernet) = group_frame(&GTK, 2, 1, b"nwifi-group");
    deliver(&h, frame);
    if !h.received(&ethernet) {
        return Err("decrypted native-WiFi group MSDU dropped");
    }
    Ok(())
}
fn smoke_ath10k_nwifi_composed_wpa2_data_and_group_rekey() -> TestResult {
    match conversation() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/ath10k/nwifi",
    smoke_ath10k_nwifi_composed_wpa2_data_and_group_rekey
);

/// WOWLAN firmware without RAW mode now has a station data owner, so the
/// native-WiFi advertisement (`WOW_MAX_REDUCE` patterns) is reachable and a
/// pattern configuration is accepted.
fn smoke_ath10k_nwifi_wowlan_advertised_with_patterns() -> TestResult {
    let h = harness(true);
    if h.join().is_err() {
        return TestResult::Fail("native-WiFi WoW station join");
    }
    h.pump();
    let Some(support) = h.device.wowlan_support() else {
        return TestResult::Fail("WOWLAN not advertised on native-WiFi firmware");
    };
    if !support.disconnect || !support.magic_packet || support.max_patterns != 22 {
        return TestResult::Fail("native-WiFi WoW advertisement");
    }
    let config = WowlanConfig {
        patterns: vec![WowlanPattern {
            mask: vec![1],
            pattern: vec![0xaa],
            offset: 0,
        }],
        ..WowlanConfig::default()
    };
    if h.device.set_wowlan(Some(config)).is_err() {
        return TestResult::Fail("native-WiFi wake pattern refused");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/nwifi",
    smoke_ath10k_nwifi_wowlan_advertised_with_patterns
);

use super::wow_conversation_tests::{interleave, word, Holder};

fn wow_fixture(h: &Harness, reason: u32) {
    h.model(|m| {
        m.wow = Some(super::super::wow_native::Fixture {
            reason,
            commands: Vec::new(),
        })
    });
}
fn wow_commands(h: &Harness) -> Vec<Vec<u8>> {
    h.model(|m| m.wow.as_ref().unwrap().commands.clone())
}
/// `ath10k_wow_vif_cleanup`: 24 event disables then 22 pattern deletes.
fn cleanup_ok(commands: &[Vec<u8>]) -> bool {
    commands.len() >= 46
        && commands[..24]
            .iter()
            .enumerate()
            .all(|(i, c)| word(c, 0) == 0x13003 && word(c, 12) == 0 && word(c, 16) == 1 << i)
        && commands[24..46]
            .iter()
            .enumerate()
            .all(|(i, c)| word(c, 0) == 0x13002 && word(c, 12) == i as u32)
}
fn enables_ok(commands: &[Vec<u8>], events: &[u32]) -> bool {
    commands.len() == events.len()
        && commands
            .iter()
            .zip(events)
            .all(|(c, &e)| word(c, 0) == 0x13003 && word(c, 12) == 1 && word(c, 16) == 1 << e)
}

/// Native-WiFi decap WoW conversation (Linux `ath10k_wow_op_suspend` ->
/// `ath10k_wow_op_resume` with `rx_decap_mode == NATIVE_WIFI`): the
/// pattern goes through `ath10k_wow_convert_8023_to_80211` into one
/// ADD_WAKE_PATTERN, a PATTERN_MATCH wake keeps the association, and the
/// next uplink is still a firmware-encrypted native-WiFi MSDU the AP
/// accepts.
fn nwifi_wow_conversation() -> Result<(), &'static str> {
    let h = harness(true);
    wow_fixture(&h, 9);
    h.join()?;
    h.pump();
    let config = WowlanConfig {
        disconnect: true,
        magic_packet: true,
        patterns: vec![WowlanPattern {
            mask: vec![1],
            pattern: vec![0xaa],
            offset: 0,
        }],
        ..WowlanConfig::default()
    };
    h.device
        .set_wowlan(Some(config.clone()))
        .map_err(|_| "native-WiFi SET_WOWLAN refused")?;
    let (arming, holder) = h
        .device
        .wow_suspend()
        .map_err(|_| "WoW program refused")?
        .ok_or("associated native-WiFi station not eligible")?;
    let mut holder: Holder = Some(Box::pin(holder));
    let Poll::Ready(Ok(suspended)) = interleave(&mut holder, arming.armed()) else {
        return Err("WOW_ENABLE suspend-complete not observed");
    };
    if h.device.radio.try_lock().is_some() {
        return Err("WoW-armed radio reachable by the worker");
    }
    let Poll::Ready(result) = interleave(&mut holder, suspended.resume()) else {
        return Err("WOW_WAKEUP_HOST not observed");
    };
    result.map_err(|_| "pattern wake dropped the association")?;
    let report = h.device.wowlan_wakeup().ok_or("no wake report")?;
    if report.reason != 9 || report.connection_lost() {
        return Err("pattern-match wake report");
    }
    let commands = wow_commands(&h);
    // cleanup, one pattern, BMISS/DEAUTH/MAGIC/DISASSOC/PATTERN/CSA,
    // ENABLE, HOSTWAKEUP.
    let events = [0u32, 2, 3, 8, 9, 10];
    if commands.len() != 46 + 1 + events.len() + 2
        || !cleanup_ok(&commands)
        || word(&commands[46], 0) != 0x13001
        || !enables_ok(&commands[47..53], &events)
        || word(&commands[53], 0) != 0x13004
        || word(&commands[54], 0) != 0x13005
    {
        return Err("Linux wow.c native-WiFi command order");
    }
    if !h.device.link_up() || h.device.wowlan_config() != Some(config) {
        return Err("carrier or SET_WOWLAN state lost across WoW");
    }
    let (up, _) = packets();
    let sent = native(&h, |f| f.native_tx);
    narf_net::iface::send_on(&h.name, &up).map_err(|_| "post-resume uplink")?;
    h.pump();
    if !h.model(|m| m.data.as_ref().unwrap().uplink.contains(&up))
        || native(&h, |f| f.native_tx) != sent + 1
    {
        return Err("post-resume uplink was not a native-WiFi MSDU the AP accepted");
    }
    Ok(())
}
fn smoke_ath10k_nwifi_wow_pattern_suspend_resume_keeps_link() -> TestResult {
    match nwifi_wow_conversation() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/ath10k/nwifi",
    smoke_ath10k_nwifi_wow_pattern_suspend_resume_keeps_link
);

/// Disconnected net-detect (Linux `ath10k_vif_wow_set_wakeups` on an
/// unassociated STA vdev with `wowlan->nd_config`): the home vdev gets the
/// cleanup, the NLO start (`ath10k_wmi_wow_config_pno`) and only the
/// NLO_DETECTED wake event; an NLOD wake stops PNO after
/// WOW_WAKEUP_HOST (`ath10k_wow_nlo_cleanup`) and leaves a usable,
/// still-unassociated station that can join afterwards. Without
/// net-detect an unassociated station still suspends ordinarily.
fn net_detect_conversation() -> Result<(), &'static str> {
    let h = harness_with(true, true);
    wow_fixture(&h, 0);
    let support = h.device.wowlan_support().ok_or("WOWLAN not advertised")?;
    if support.net_detect_max_match_sets != 16 {
        return Err("NET_DETECT not advertised with WMI_TLV_SERVICE_NLO");
    }
    h.device
        .set_wowlan(Some(WowlanConfig {
            magic_packet: true,
            ..WowlanConfig::default()
        }))
        .map_err(|_| "magic SET_WOWLAN refused")?;
    if !matches!(h.device.wow_suspend(), Ok(None)) {
        return Err("unassociated station without net-detect entered WoW");
    }
    let config = WowlanConfig {
        net_detect: Some(narf_wireless::NetDetectConfig {
            probe_ssids: Vec::new(),
            frequencies_mhz: vec![2412],
            probe_ies: Vec::new(),
            matches: vec![narf_wireless::NetDetectMatch {
                ssid: b"narf-wow".to_vec(),
                rssi_threshold_dbm: None,
            }],
            plans: vec![narf_wireless::NetDetectScanPlan {
                interval_secs: 30,
                iterations: None,
            }],
            delay_secs: 0,
            random_mac: None,
        }),
        ..WowlanConfig::default()
    };
    h.device
        .set_wowlan(Some(config))
        .map_err(|_| "net-detect SET_WOWLAN refused")?;
    if h.device.link_up() {
        return Err("fixture station already associated");
    }
    let (arming, holder) = h
        .device
        .wow_suspend()
        .map_err(|_| "net-detect WoW program refused")?
        .ok_or("disconnected net-detect took the ordinary suspend")?;
    let mut holder: Holder = Some(Box::pin(holder));
    let Poll::Ready(Ok(suspended)) = interleave(&mut holder, arming.armed()) else {
        return Err("net-detect WOW_ENABLE not acknowledged");
    };
    let Poll::Ready(result) = interleave(&mut holder, suspended.resume()) else {
        return Err("WOW_WAKEUP_HOST not observed");
    };
    result.map_err(|_| "NLOD wake failed the generation")?;
    let report = h.device.wowlan_wakeup().ok_or("no wake report")?;
    if report.reason != 0 || report.connection_lost() {
        return Err("NLOD wake report");
    }
    let commands = wow_commands(&h);
    // cleanup, NLO start, NLO_DETECTED enable, ENABLE, HOSTWAKEUP, NLO stop.
    if commands.len() != 46 + 1 + 1 + 3
        || !cleanup_ok(&commands)
        || word(&commands[46], 0) != 0x18001
        || !enables_ok(&commands[47..48], &[7])
        || word(&commands[48], 0) != 0x13004
        || word(&commands[49], 0) != 0x13005
        || word(&commands[50], 0) != 0x18001
    {
        return Err("Linux wow.c net-detect command order");
    }
    // Every command named the same (home) vdev. The NLO config carries
    // `flags` first and `vdev_id` second (`wmi_tlv_wow_nlo_config_cmd`).
    let vdev = word(&commands[0], 8);
    let vdev_of = |c: &Vec<u8>| word(c, if word(c, 0) == 0x18001 { 12 } else { 8 });
    if commands[..48].iter().any(|c| vdev_of(c) != vdev) || vdev_of(&commands[50]) != vdev {
        return Err("net-detect commands on different vdevs");
    }
    h.join()
        .map_err(|_| "station could not join after a net-detect wake")?;
    if !h.device.link_up() {
        return Err("no carrier after the post-wake join");
    }
    Ok(())
}
fn smoke_ath10k_wow_disconnected_net_detect_suspend_resume() -> TestResult {
    match net_detect_conversation() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/ath10k/wow",
    smoke_ath10k_wow_disconnected_net_detect_suspend_resume
);
