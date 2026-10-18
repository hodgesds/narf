//! wpa_supplicant's `-Dnl80211` sequence against a handshake-offloading
//! driver, end to end: capability probing, mode set, scan, a WPA2-PSK
//! CONNECT carrying the PMK, and the CONNECT + PORT_AUTHORIZED events the
//! supplicant waits for. The fake driver runs a real 4-way handshake
//! (HMAC-SHA1 PRF + Key MICs) between the shared supplicant state machine
//! and a test authenticator holding the AP's PMK, so a wrong passphrase
//! fails the MIC check the same way it would on the air.

use super::*;
use crate::eapol::{
    derive_ptk, eapol_key_mic, HmacPrimitive, KeyFrame, Supplicant, KEY_DESCRIPTOR_RSN, KI_INSTALL,
    KI_KEY_ACK, KI_KEY_MIC, KI_KEY_TYPE_PAIRWISE, KI_SECURE, KI_VERSION_HMAC_SHA1_AES,
};
use narf_net::netlink_generic::{build_replies_with_context, install_event_sink, ReplyOptions};

const E2E_NAME: &str = "wlan-wpas";
const E2E_MAC: [u8; 6] = [2, 0x5a, 0x5b, 0x5c, 0x5d, 0x01];
const AP_BSSID: [u8; 6] = [2, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4];
const AP_SSID: &[u8] = b"narf-psk";
const AP_PASSPHRASE: &[u8] = b"correct horse battery";
const AP_CHANNEL: u32 = 6;
/// Offset of the Key MIC in an EAPOL-Key PDU (4-byte EAPOL header + 77).
const MIC_OFFSET: usize = 81;

struct Sha1;
impl HmacPrimitive for Sha1 {
    fn out_len(&self) -> usize {
        20
    }
    fn mac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        narf_crypto::pbkdf2_sha1::hmac_sha1(key, data).to_vec()
    }
}

fn psk(passphrase: &[u8]) -> [u8; 32] {
    narf_crypto::pbkdf2_sha1::pbkdf2_hmac_sha1(passphrase, AP_SSID, 4096, 32)
        .try_into()
        .unwrap()
}

fn rsn_element() -> Vec<u8> {
    let body = crate::rsn::RsnIe::wpa2_psk_ccmp().encode_body();
    let mut ie = alloc::vec![48, body.len() as u8];
    ie.extend_from_slice(&body);
    ie
}

/// Stamp `pdu`'s Key MIC (computed with the field zeroed).
fn sign(kck: &[u8], pdu: &mut [u8]) {
    pdu[MIC_OFFSET..MIC_OFFSET + 16].fill(0);
    let mic = eapol_key_mic(KI_VERSION_HMAC_SHA1_AES, kck, pdu, 16).unwrap();
    pdu[MIC_OFFSET..MIC_OFFSET + 16].copy_from_slice(&mic);
}

/// Does `pdu` carry the Key MIC `kck` produces?
fn verify(kck: &[u8], pdu: &[u8]) -> bool {
    let mut copy = pdu.to_vec();
    sign(kck, &mut copy);
    copy == pdu
}

/// One 4-way handshake: `sta_pmk` drives the shared supplicant, the test
/// authenticator holds the AP's PMK. True when M2, M3 and M4 all verify and
/// both sides derived the same TK.
fn four_way(sta_pmk: &[u8; 32]) -> bool {
    let (aa, sa) = (AP_BSSID, E2E_MAC);
    let ap_pmk = psk(AP_PASSPHRASE);
    let anonce = [0x4au8; 32];
    let mut sup = Supplicant::new(aa, sa, [0x5bu8; 32]);
    let version = KI_VERSION_HMAC_SHA1_AES;

    let mut m1 = KeyFrame::empty(16);
    m1.descriptor_type = KEY_DESCRIPTOR_RSN;
    m1.key_information = version | KI_KEY_TYPE_PAIRWISE | KI_KEY_ACK;
    m1.key_length = 16;
    m1.replay_counter = 1;
    m1.key_nonce = anonce;
    let Ok(Some(mut m2)) = sup.handle(&Sha1, sta_pmk, 16, &m1) else {
        return false;
    };
    m2.key_data = rsn_element();
    let mut m2 = m2.into_eapol();
    let sta_kck = sup.ptk.as_ref().unwrap().kck.clone();
    sign(&sta_kck, &mut m2);

    // Authenticator: derive from M2's SNonce, check its MIC.
    let Some(m2_key) = KeyFrame::decode(&m2[4..], 16) else {
        return false;
    };
    let ap_ptk = derive_ptk(&Sha1, &ap_pmk, &aa, &sa, &anonce, &m2_key.key_nonce, 16);
    if !verify(&ap_ptk.kck, &m2) {
        return false;
    }
    let mut m3 = KeyFrame::empty(16);
    m3.descriptor_type = KEY_DESCRIPTOR_RSN;
    m3.key_information =
        version | KI_KEY_TYPE_PAIRWISE | KI_KEY_ACK | KI_KEY_MIC | KI_INSTALL | KI_SECURE;
    m3.key_length = 16;
    m3.replay_counter = 2;
    m3.key_nonce = anonce;
    m3.key_data = rsn_element();
    let mut m3 = m3.into_eapol();
    sign(&ap_ptk.kck, &mut m3);

    // Supplicant: verify M3 (as `wpa_supplicant_verify_eapol_key_mic`),
    // answer M4.
    if !verify(&sta_kck, &m3) {
        return false;
    }
    let Some(m3_key) = KeyFrame::decode(&m3[4..], 16) else {
        return false;
    };
    let Ok(Some(m4)) = sup.handle(&Sha1, sta_pmk, 16, &m3_key) else {
        return false;
    };
    let mut m4 = m4.into_eapol();
    sign(&sta_kck, &mut m4);
    verify(&ap_ptk.kck, &m4) && sup.ptk.as_ref().unwrap().tk == ap_ptk.tk
}

/// A handshake-offloading station (ath11k / iwlwifi / mt7921 shape): the
/// driver runs the 4-way handshake itself from the PMK in CONNECT.
struct PskStub {
    rx: IrqSafeSpinLock<Option<narf_ipc::Consumer<narf_net::Frame, { narf_net::RX_RING_N }>>>,
    tx: IrqSafeSpinLock<Option<narf_ipc::Producer<narf_net::Frame, { narf_net::TX_RING_N }>>>,
    connected: IrqSafeSpinLock<Option<[u8; 6]>>,
}
impl narf_net::Interface for PskStub {
    fn name(&self) -> &str {
        E2E_NAME
    }
    fn mac(&self) -> [u8; 6] {
        E2E_MAC
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.connected.lock().is_some()
    }
    fn rx_ring(
        &self,
    ) -> &IrqSafeSpinLock<Option<narf_ipc::Consumer<narf_net::Frame, { narf_net::RX_RING_N }>>>
    {
        &self.rx
    }
    fn tx_ring(
        &self,
    ) -> &IrqSafeSpinLock<Option<narf_ipc::Producer<narf_net::Frame, { narf_net::TX_RING_N }>>>
    {
        &self.tx
    }
}
#[async_trait::async_trait]
impl crate::WirelessNetIface for PskStub {
    fn supports_handshake_offload(&self) -> bool {
        true
    }
    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        (bssid == AP_BSSID).then(|| {
            let mut ies = alloc::vec![0, AP_SSID.len() as u8];
            ies.extend_from_slice(AP_SSID);
            ies.extend_from_slice(&rsn_element());
            ies
        })
    }
    fn get_wireless_info(&self) -> crate::WirelessIfaceInfo {
        crate::WirelessIfaceInfo {
            base_name: E2E_NAME.into(),
            base_mac: E2E_MAC,
            bands: alloc::vec![crate::iface::WirelessBand {
                freq_mhz: 2400,
                channels: alloc::vec![1, 6, 11],
            }],
            modes: crate::iface::WirelessModes::STATION,
            hw_caps: crate::iface::HwCaps {
                ht_supported: true,
                vht_supported: false,
                he_supported: false,
                eht_supported: false,
            },
        }
    }
    async fn scan(
        &self,
        _: crate::ScanRequest,
    ) -> Result<Vec<crate::BssInfo>, crate::WirelessError> {
        Ok(alloc::vec![crate::BssInfo {
            bssid: AP_BSSID,
            ssid: AP_SSID.to_vec(),
            channel: AP_CHANNEL,
            rssi: -51,
            security: crate::scan::BssSecurity::Wpa2,
        }])
    }
    async fn associate(&self, req: crate::AssociateRequest) -> Result<(), crate::WirelessError> {
        let crate::SecurityConfig::Wpa2 { psk } = req.security else {
            return Err(crate::WirelessError::InvalidArgs);
        };
        if req.bssid != AP_BSSID || !four_way(&psk) {
            return Err(crate::WirelessError::Denied);
        }
        *self.connected.lock() = Some(req.bssid);
        Ok(())
    }
    async fn disassociate(&self) -> Result<(), crate::WirelessError> {
        *self.connected.lock() = None;
        Ok(())
    }
    fn connected_bssid(&self) -> Option<[u8; 6]> {
        *self.connected.lock()
    }
    async fn set_config(&self, _: crate::WirelessConfig) -> Result<(), crate::WirelessError> {
        Err(crate::WirelessError::NotSupported)
    }
}

static EVENTS: IrqSafeSpinLock<Vec<(u32, Vec<u8>)>> = IrqSafeSpinLock::new(Vec::new());
fn capture(_: u64, group: u32, message: &[u8]) {
    EVENTS.lock().push((group, message.to_vec()));
}
struct Restore(Option<fn(u64, u32, &[u8])>);
impl Drop for Restore {
    fn drop(&mut self) {
        if let Some(previous) = self.0 {
            install_event_sink(previous);
        }
        CACHE.lock().retain(|c| c.name != E2E_NAME);
    }
}

fn message(family: u16, command: u8, flags: u16, attrs: &[u8]) -> Vec<u8> {
    let mut body = alloc::vec![command, 1, 0, 0];
    body.extend_from_slice(attrs);
    let len = 16 + body.len();
    let mut out = Vec::new();
    out.extend_from_slice(&(len as u32).to_ne_bytes());
    out.extend_from_slice(&family.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&9u32.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(&body);
    out
}

/// Send one request; the replies, or the negative errno of an error reply.
fn send(
    command: u8,
    flags: u16,
    attrs: &[u8],
    context: RequestContext<'_>,
) -> Result<Vec<Vec<u8>>, i32> {
    let replies = build_replies_with_context(
        &message(NL80211_FAMILY_ID, command, flags, attrs),
        ReplyOptions::default(),
        context,
    )
    .map_err(|_| -1)?;
    match replies.first() {
        Some(r) if u16::from_ne_bytes(r[4..6].try_into().unwrap()) == 2 => {
            let errno = -i32::from_ne_bytes(r[16..20].try_into().unwrap());
            if errno == 0 {
                Ok(replies)
            } else {
                Err(errno)
            }
        }
        _ => Ok(replies),
    }
}

fn ifindex_attr(ifindex: u32) -> Vec<u8> {
    let mut attrs = Vec::new();
    push_attr(&mut attrs, 3, &ifindex.to_ne_bytes());
    attrs
}

/// The CONNECT wpa_supplicant builds for a WPA2-PSK network on a driver
/// with WPA_DRIVER_FLAGS_4WAY_HANDSHAKE_PSK (`nl80211_connect_common` and
/// `wpa_driver_nl80211_try_connect`), with the HT override masks a
/// CONFIG_HT_OVERRIDES build always adds.
fn wpa_supplicant_connect(ifindex: u32, pmk: &[u8; 32]) -> Vec<u8> {
    let mut a = ifindex_attr(ifindex);
    push_attr(&mut a, 204, &[]); // IFACE_SOCKET_OWNER
    push_attr(&mut a, 200, &AP_BSSID); // MAC_HINT
    push_attr(&mut a, 201, &2437u32.to_ne_bytes()); // WIPHY_FREQ_HINT
    push_attr(&mut a, 52, AP_SSID);
    let mut ie = rsn_element();
    ie.extend_from_slice(&[127, 8, 0, 0, 0, 0, 0, 0, 0, 0x40]); // Extended Capabilities
    push_attr(&mut a, 42, &ie);
    push_attr(&mut a, 75, &2u32.to_ne_bytes()); // WPA_VERSIONS = RSN
    push_attr(&mut a, 73, &0x000fac04u32.to_ne_bytes()); // pairwise CCMP
    push_attr(&mut a, 74, &0x000fac04u32.to_ne_bytes()); // group CCMP
    push_attr(&mut a, 76, &0x000fac02u32.to_ne_bytes()); // AKM PSK
    push_attr(&mut a, 254, pmk); // PMK
    push_attr(&mut a, 68, &[]); // CONTROL_PORT
    push_attr(&mut a, 102, &0x888eu16.to_ne_bytes()); // CONTROL_PORT_ETHERTYPE
    push_attr(&mut a, 31, &[0; 26]); // HT_CAPABILITY
    push_attr(&mut a, 148, &[0; 26]); // HT_CAPABILITY_MASK
    push_attr(&mut a, 315, &[]); // MLO_SUPPORT
    push_attr(&mut a, 53, &0u32.to_ne_bytes()); // AUTH_TYPE = OPEN_SYSTEM
    a
}

fn connect_operation(attrs: &[u8]) -> Result<Operation, i32> {
    parse_operation(CONNECT, &attributes(attrs)?, true, false)
}

fn bss_status(replies: &[Vec<u8>]) -> Option<Option<u32>> {
    replies.iter().find_map(|r| {
        let bss = find_attr(&r[20..], 47 | NLA_F_NESTED)?;
        (find_attr(bss, 1)? == AP_BSSID)
            .then(|| find_attr(bss, 9).map(|s| u32::from_ne_bytes(s.try_into().unwrap())))
    })
}

fn smoke_nl80211_wpa_supplicant_wpa2_psk_end_to_end() -> TestResult {
    register();
    let _restore = Restore(install_event_sink(capture));
    let iface: Arc<dyn crate::WirelessNetIface> = Arc::new(PskStub {
        rx: IrqSafeSpinLock::new(None),
        tx: IrqSafeSpinLock::new(None),
        connected: IrqSafeSpinLock::new(None),
    });
    narf_net::iface::register(E2E_NAME, E2E_MAC, |_, _| Ok(()));
    crate::registry::register(iface.clone());
    let Some(ifindex) = narf_net::netlink_route::ifindex_for_name(E2E_NAME) else {
        return TestResult::Fail("e2e stub has no ifindex");
    };
    let root = RequestContext {
        init_net_admin: true,
        net_admin: true,
        ..RequestContext::default()
    };
    let nobody = RequestContext::default();
    const REQ: u16 = 5; // NLM_F_REQUEST | NLM_F_ACK
    const DUMP: u16 = 0x301;

    // wpa_driver_nl80211_get_info: GET_WIPHY by ifindex (+ SPLIT flag).
    let mut attrs = ifindex_attr(ifindex);
    push_attr(&mut attrs, 174, &[]); // NL80211_ATTR_SPLIT_WIPHY_DUMP
    let Ok(replies) = send(NL80211_CMD_GET_WIPHY, REQ, &attrs, nobody) else {
        return TestResult::Fail("GET_WIPHY by ifindex failed");
    };
    let wiphy = &replies[0][20..];
    let commands: Vec<u32> = find_attr(wiphy, NL80211_ATTR_SUPPORTED_COMMANDS | NLA_F_NESTED)
        .map(|c| {
            c.chunks(8)
                .filter(|e| e.len() == 8)
                .map(|e| u32::from_ne_bytes(e[4..8].try_into().unwrap()))
                .collect()
        })
        .unwrap_or_default();
    // CONNECT without AUTHENTICATE: wpa_supplicant uses the driver SME.
    if !commands.contains(&46) || commands.contains(&37) {
        return TestResult::Fail("GET_WIPHY commands do not select the CONNECT path");
    }
    if find_attr(wiphy, 57) != Some(&0x000fac04u32.to_ne_bytes()[..])
        || !find_attr(wiphy, 217).is_some_and(|ext| ext.len() >= 2 && ext[1] & 0x80 != 0)
    {
        return TestResult::Fail("GET_WIPHY lacks CCMP / 4WAY_HANDSHAKE_STA_PSK");
    }
    // __cfg80211_rdev_from_attrs: no selector -EINVAL, no such netdev -ENODEV.
    if send(NL80211_CMD_GET_WIPHY, REQ, &[], nobody) != Err(EINVAL)
        || send(
            NL80211_CMD_GET_WIPHY,
            REQ,
            &ifindex_attr(0x7fff_0000),
            nobody,
        ) != Err(ENODEV)
    {
        return TestResult::Fail("GET_WIPHY selector errnos");
    }

    // nl80211_set_mode(STATION): the current type is a no-op success.
    let set_type = |iftype: u32, context| {
        let mut a = ifindex_attr(ifindex);
        push_attr(&mut a, 5, &iftype.to_ne_bytes());
        send(SET_INTERFACE, REQ, &a, context).map(|_| ())
    };
    if set_type(2, root) != Ok(())
        || set_type(3, root) != Err(EOPNOTSUPP)
        || set_type(13, root) != Err(EINVAL)
        || set_type(2, nobody) != Err(EPERM)
    {
        return TestResult::Fail("SET_INTERFACE errnos");
    }

    // TRIGGER_SCAN as wpa_supplicant sends its first scan: wildcard SSID +
    // NL80211_SCAN_FLAG_FLUSH.
    let mut scan = ifindex_attr(ifindex);
    let mut ssids = Vec::new();
    push_attr(&mut ssids, 1, &[]);
    push_attr(&mut scan, 45 | NLA_F_NESTED, &ssids);
    let mut with_flags = scan.clone();
    push_attr(&mut with_flags, 158, &(1u32 << 1).to_ne_bytes());
    let Ok(Operation::Scan(request)) =
        parse_operation(SCAN, &attributes(&with_flags).unwrap(), true, false)
    else {
        return TestResult::Fail("wpa_supplicant TRIGGER_SCAN (FLUSH) refused");
    };
    let mut random = scan.clone();
    push_attr(&mut random, 158, &(1u32 << 3).to_ne_bytes());
    let mut probe_ies = scan.clone();
    push_attr(&mut probe_ies, 42, &[127, 1, 0]);
    if parse_operation(SCAN, &attributes(&random).unwrap(), true, false).err() != Some(EOPNOTSUPP)
        || parse_operation(SCAN, &attributes(&probe_ies).unwrap(), true, false).err()
            != Some(EINVAL)
    {
        return TestResult::Fail("scan flag / probe IE errnos");
    }
    let admin = narf_net::kernel_admin(E2E_NAME).unwrap();
    CACHE.lock().retain(|c| c.name != E2E_NAME);
    CACHE.lock().push(Cache {
        name: E2E_NAME.into(),
        namespace: 0,
        busy: true,
        results: Vec::new(),
    });
    EVENTS.lock().clear();
    narf_scheduler::block_on_spin(execute(
        iface.clone(),
        admin.clone(),
        0,
        ifindex,
        Operation::Scan(request),
    ));
    if !EVENTS.lock().iter().any(|(g, m)| *g == 18 && m[16] == 34) {
        return TestResult::Fail("no NEW_SCAN_RESULTS on the scan group");
    }
    let Ok(dump) = send(GET_SCAN, DUMP, &ifindex_attr(ifindex), nobody) else {
        return TestResult::Fail("GET_SCAN dump failed");
    };
    if bss_status(&dump) != Some(None) {
        return TestResult::Fail("unassociated BSS missing, or carries BSS_STATUS");
    }

    // CONNECT: the attribute set is accepted and decodes to the PMK path.
    let pmk = psk(AP_PASSPHRASE);
    let connect = wpa_supplicant_connect(ifindex, &pmk);
    if send(CONNECT, REQ, &connect, nobody) != Err(EPERM) {
        return TestResult::Fail("CONNECT without CAP_NET_ADMIN was not EPERM");
    }
    let Ok(operation) = connect_operation(&connect) else {
        return TestResult::Fail("wpa_supplicant's WPA2-PSK CONNECT was refused");
    };
    if !matches!(&operation, Operation::Connect { cred: Credential::Psk(p), .. } if **p == pmk) {
        return TestResult::Fail("CONNECT did not carry the PMK to the driver");
    }
    // nl80211_connect's own checks on those attributes.
    let mut no_mask = ifindex_attr(ifindex);
    push_attr(&mut no_mask, 52, AP_SSID);
    push_attr(&mut no_mask, 31, &[0; 26]);
    let mut ethertype = ifindex_attr(ifindex);
    push_attr(&mut ethertype, 52, AP_SSID);
    push_attr(&mut ethertype, 102, &0x0800u16.to_ne_bytes());
    let mut pae_over_nl = ifindex_attr(ifindex);
    push_attr(&mut pae_over_nl, 52, AP_SSID);
    push_attr(&mut pae_over_nl, 264, &[]);
    if connect_operation(&no_mask).err() != Some(EINVAL)
        || connect_operation(&ethertype).err() != Some(EINVAL)
        || connect_operation(&pae_over_nl).err() != Some(EOPNOTSUPP)
    {
        return TestResult::Fail("CONNECT override / control-port errnos");
    }

    // The offloaded connect: CONNECT(status 0) then PORT_AUTHORIZED.
    EVENTS.lock().clear();
    narf_scheduler::block_on_spin(execute(iface.clone(), admin.clone(), 0, ifindex, operation));
    let events: Vec<(u32, Vec<u8>)> = EVENTS.lock().clone();
    let connect_at = events.iter().position(|(g, m)| {
        *g == 19
            && m[16] == CONNECT
            && find_attr(&m[20..], 72) == Some(&0u16.to_ne_bytes()[..])
            && find_attr(&m[20..], 6) == Some(&AP_BSSID[..])
            && find_attr(&m[20..], 1).is_some()
    });
    let authorized_at = events.iter().position(|(g, m)| {
        *g == 19 && m[16] == PORT_AUTHORIZED && find_attr(&m[20..], 6) == Some(&AP_BSSID[..])
    });
    match (connect_at, authorized_at) {
        (Some(c), Some(a)) if c < a => {}
        _ => return TestResult::Fail("no CONNECT success followed by PORT_AUTHORIZED"),
    }

    // Link state as `iw link` and wpa_supplicant's signal poll read it.
    let Ok(dump) = send(GET_SCAN, DUMP, &ifindex_attr(ifindex), nobody) else {
        return TestResult::Fail("GET_SCAN dump failed after connect");
    };
    if bss_status(&dump) != Some(Some(1)) {
        return TestResult::Fail("associated BSS lacks NL80211_BSS_STATUS_ASSOCIATED");
    }
    let mut station = ifindex_attr(ifindex);
    push_attr(&mut station, 6, &AP_BSSID);
    let Ok(replies) = send(GET_STATION, REQ, &station, nobody) else {
        return TestResult::Fail("GET_STATION for the AP failed");
    };
    let sta = &replies[0][20..];
    if replies[0][16] != NEW_STATION
        || find_attr(sta, 6) != Some(&AP_BSSID[..])
        || find_attr(sta, 21 | NLA_F_NESTED).and_then(|info| find_attr(info, 7))
            != Some(&[(-51i8) as u8][..])
    {
        return TestResult::Fail("GET_STATION reply lacks the AP or its signal");
    }
    let mut other = ifindex_attr(ifindex);
    push_attr(&mut other, 6, &[2, 9, 9, 9, 9, 9]);
    if send(GET_STATION, REQ, &other, nobody) != Err(ENOENT)
        || send(GET_STATION, REQ, &ifindex_attr(ifindex), nobody) != Err(EINVAL)
    {
        return TestResult::Fail("GET_STATION errnos");
    }

    // A wrong passphrase fails the authenticator's M2 MIC check: CONNECT
    // reports failure and the port is never authorized.
    narf_scheduler::block_on_spin(execute(
        iface.clone(),
        admin.clone(),
        0,
        ifindex,
        Operation::Disconnect,
    ));
    EVENTS.lock().clear();
    let Ok(bad) = connect_operation(&wpa_supplicant_connect(ifindex, &psk(b"wrong horse"))) else {
        return TestResult::Fail("wrong-passphrase CONNECT refused at parse");
    };
    narf_scheduler::block_on_spin(execute(iface.clone(), admin, 0, ifindex, bad));
    let events = EVENTS.lock().clone();
    if !events
        .iter()
        .any(|(_, m)| m[16] == CONNECT && find_attr(&m[20..], 72) != Some(&0u16.to_ne_bytes()[..]))
        || events.iter().any(|(_, m)| m[16] == PORT_AUTHORIZED)
        || iface.connected_bssid().is_some()
    {
        return TestResult::Fail("wrong passphrase was not a failed, unauthorized connect");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/nl80211",
    smoke_nl80211_wpa_supplicant_wpa2_psk_end_to_end
);
