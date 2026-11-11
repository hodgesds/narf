//! Composed hardware-key conversation (Linux `rawmode=1 cryptmode=0`, the
//! PCI radio's default profile) over the actual CE/HTT/WMI/netdev path. The
//! model firmware holds a key cache filled only by `WMI_VDEV_INSTALL_KEY`,
//! answers each install with the HTT `SEC_IND`, encrypts header-only RAW TX,
//! decrypts RAW RX and PMF unicast management with the programmed keys, and
//! the independent FakeAp still checks every MPDU with its own PTK.
use super::*;
use narf_wifi_fixtures::ApPmf;

const GTK_A: [u8; 16] = [0x66; 16];
/// Distinct from the message-3 GTK the FakeAp hands out ([0x77; 16], key
/// 1): reusing earlier material is refused as KeyReuse.
const GTK_B: [u8; 16] = [0x88; 16];

fn harness(version: u32, dialect: Dialect) -> Harness {
    let hardware = if dialect == Dialect::Tlv {
        HwRev::Qca6174
    } else {
        HwRev::Qca988x
    };
    let h = Harness::new_on_firmware(
        version,
        dialect,
        true,
        false,
        2412,
        0x64,
        NativeFirmware {
            ht: None,
            radio: RadioSource {
                hardware,
                rf_chains: 2,
                vht: None,
            },
            all_inventory: false,
            // RAW decap, WMI management TX, ATH10K_FW_FEATURE_MFP_SUPPORT.
            features: (1 << 10)
                | (1 << 2)
                | (1 << 12)
                | if dialect == Dialect::Tlv { 1 << 18 } else { 0 },
            htt: (3, 1),
            hardware_keys: true,
            nlo: false,
        },
    );
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        f.ap = FakeAp::wpa2(network(), b"narf", 1, 7, PMK, ANONCE)
            .and_then(|ap| ap.with_pmf(ApPmf::Required))
            .unwrap();
        // wmi.h WMI_PEER_PMF / WMI_10_2_PEER_PMF, wmi-tlv.h WMI_TLV_PEER_PMF.
        f.hw = Some(Box::new(HwKeyCache {
            pmf_flag: if dialect == Dialect::Tlv {
                0x0800_0000
            } else {
                0x1000_0000
            },
            ..HwKeyCache::default()
        }));
    });
    h
}
fn hw<R>(h: &Harness, operation: impl FnOnce(&HwKeyCache) -> R) -> R {
    h.model(|m| operation(m.data.as_ref().unwrap().hw.as_ref().unwrap()))
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
fn deliver(h: &Harness, frame: Vec<u8>) {
    h.model(|m| m.data.as_mut().unwrap().queue.push_back(frame));
    h.pump();
}
/// A robust unicast management frame protected by the AP's PTK, as the
/// firmware hands it to the host after decrypting it.
fn management(h: &Harness, subtype: u8, body: &[u8], pn: u64) -> Vec<u8> {
    let mut frame = vec![subtype, 0x40, 0, 0];
    frame.extend_from_slice(&OWN);
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&[0, 0]);
    let tk = h.model(|m| m.data.as_ref().unwrap().ap.pairwise_tk().unwrap());
    let mut plain = body.to_vec();
    let wire = narf_wireless::ccmp::protect(&Ccm, &frame, &tk, pn, 0, 0, true, &mut plain).unwrap();
    frame.extend_from_slice(&wire);
    h.model(|m| m.data.as_mut().unwrap().firmware_management_rx(frame))
}
fn inject(h: &Harness, frame: Vec<u8>) {
    h.model(|m| management_frame(m, frame));
    h.pump();
}
/// Open a robust frame the firmware sent with the AP's own PTK.
fn opened(h: &Harness, frame: &[u8]) -> Option<Vec<u8>> {
    if frame.len() < 24 + 16 || frame[1] != 0x40 || frame[4..10] != AP || frame[10..16] != OWN {
        return None;
    }
    let tk = h.model(|m| m.data.as_ref().unwrap().ap.pairwise_tk().unwrap());
    let mut replay = narf_wireless::ccmp::ReplayWindow { last_seen_pn: 0 };
    let mut body = frame[24..].to_vec();
    narf_wireless::ccmp::unprotect(&Ccm, &frame[..24], &tk, 0, true, &mut replay, &mut body).ok()
}
/// A group-key handshake for `gtk` in slot 2 (`group_replay` advanced).
fn rekey(h: &Harness, gtk: [u8; 16], replay: u64) {
    let frame = h.model(|m| {
        let f = m.data.as_mut().unwrap();
        f.group_replay = replay;
        f.group_rekey_with(2, gtk)
    });
    deliver(h, frame);
    // The device worker's step after the drain (`flush_management`)
    // programs the key the delivered group reply committed; the next drain
    // takes its SEC_IND.
    let _ = drive(h.device.flush_management());
    h.pump();
}

fn conversation(version: u32, dialect: Dialect) -> Result<(), &'static str> {
    let h = harness(version, dialect);
    h.join()?;
    h.pump();
    // Install: PTK then GTK, each confirmed by SEC_IND; IGTK stays software
    // (mac.c ath10k_set_key returns 1 for BIP). The programmed PTK is the
    // AP's own.
    let tk = h.model(|m| m.data.as_ref().unwrap().ap.pairwise_tk().unwrap());
    if hw(&h, |c| {
        c.installs != 2 || c.key(true, 0) != Some(tk) || c.keys.iter().filter(|k| !k.0).count() != 1
    }) {
        return Err("PTK/GTK not programmed once each through WMI_VDEV_INSTALL_KEY");
    }
    // TX: header-only CCMP, encrypted by the firmware at the host PN; the AP
    // opens it with its PTK and replay counter.
    let (up, down) = packets();
    narf_net::iface::send_on(&h.name, &up).map_err(|_| "hardware-key uplink")?;
    h.pump();
    if !h.model(|m| m.data.as_ref().unwrap().uplink.contains(&up)) || hw(&h, |c| c.hardware_tx) == 0
    {
        return Err("confirmed PTK did not carry header-only RAW TX through the firmware");
    }
    // RX: firmware-decrypted RAW MPDU through the PN-only path; a replay of
    // the same decrypted MPDU is dropped.
    let frame = h.model(|m| m.data.as_mut().unwrap().downlink(&down));
    let decrypted = hw(&h, |c| c.decrypted_rx);
    deliver(&h, frame.clone());
    if !h.received(&down) || hw(&h, |c| c.decrypted_rx) != decrypted + 1 {
        return Err("firmware-decrypted RAW MPDU did not reach the netdev");
    }
    deliver(&h, frame);
    if h.received(&down) {
        return Err("replayed firmware-decrypted MPDU escaped the host PN check");
    }
    // PMF: a protected SA Query arrives firmware-decrypted; the response
    // leaves header-only and the firmware encrypts it with the PTK.
    inject(&h, management(&h, 0xd0, &[8, 0, 0x34, 0x12], 1 << 20));
    if !matches!(drive(h.device.flush_management()), Poll::Ready(Ok(()))) {
        return Err("SA Query response publication failed");
    }
    let sent = h.model(|m| m.data.as_ref().unwrap().management_tx.clone());
    if sent.len() != 1
        || sent[0][0] != 0xd0
        || opened(&h, &sent[0]).as_deref() != Some(&[8, 1, 0x34, 0x12])
    {
        return Err("PMF SA Query not answered through the firmware PTK");
    }
    // Group rekey into slot 2 (GTK A): installed, confirmed, then group
    // traffic decrypted by the firmware is admitted.
    rekey(&h, GTK_A, 3);
    if hw(&h, |c| c.installs != 3 || c.key(false, 2) != Some(GTK_A)) {
        return Err("group rekey not programmed after the group reply");
    }
    let (frame, ethernet) = group_frame(&GTK_A, 2, 1, b"gtk-a-1");
    deliver(&h, frame);
    if !h.received(&ethernet) {
        return Err("firmware-decrypted group MPDU under confirmed GTK dropped");
    }
    // Recommit slot 2 (GTK B) with the install unconfirmed: the firmware
    // still holds GTK A, so a frame it decrypts under the stale key is
    // dropped; a GTK B frame it cannot decrypt keeps the software path.
    hw_hold(&h);
    rekey(&h, GTK_B, 4);
    if !hw(&h, |c| c.held() && c.installs == 4) {
        return Err("GTK B install was not sent");
    }
    let (frame, ethernet) = group_frame(&GTK_A, 2, 2, b"gtk-a-2");
    deliver(&h, frame);
    if h.received(&ethernet) {
        return Err("frame decrypted under the stale GTK admitted before SEC_IND");
    }
    let (frame, ethernet) = group_frame(&GTK_B, 2, 1, b"gtk-b-1");
    deliver(&h, frame);
    if !h.received(&ethernet) {
        return Err("software GTK B fallback dropped an undecrypted frame");
    }
    h.model(release_install);
    h.pump();
    let (frame, ethernet) = group_frame(&GTK_B, 2, 2, b"gtk-b-2");
    let decrypted = hw(&h, |c| c.decrypted_rx);
    deliver(&h, frame);
    if !h.received(&ethernet) || hw(&h, |c| c.decrypted_rx) != decrypted + 1 {
        return Err("confirmed GTK B did not admit firmware-decrypted traffic");
    }
    // PMF: a replayed protected deauthentication is dropped; a fresh one
    // ends the link.
    inject(&h, management(&h, 0xc0, &[3, 0], 1 << 20));
    if !h.device.link_up() {
        return Err("replayed firmware-decrypted deauthentication accepted");
    }
    inject(&h, management(&h, 0xc0, &[3, 0], (1 << 20) + 1));
    if !h.closed() || !h.model(|m| m.ce.as_ref().unwrap().retained()) {
        return Err("firmware-decrypted protected deauthentication ignored");
    }
    Ok(())
}
fn hw_hold(h: &Harness) {
    h.model(|m| m.data.as_mut().unwrap().hw.as_mut().unwrap().hold = true);
}

fn smoke_ath10k_hw_keys_composed_install_data_rekey_and_pmf() -> TestResult {
    for (version, dialect) in [(1, Dialect::Main), (3, Dialect::TenTwo), (4, Dialect::Tlv)] {
        if let Err(e) = conversation(version, dialect) {
            return TestResult::Fail(e);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/hw_keys",
    smoke_ath10k_hw_keys_composed_install_data_rekey_and_pmf
);
