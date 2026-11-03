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
