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
    fn max_scan_ssids(&self) -> u8 {
        16
    }

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
            frequency_mhz: 2407 + 5 * AP_CHANNEL,
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
    // NetworkManager's split dump narrows to the netdev's wiphy.
    let Ok(dump) = send(NL80211_CMD_GET_WIPHY, DUMP, &attrs, nobody) else {
        return TestResult::Fail("GET_WIPHY split dump failed");
    };
    let wiphys: Vec<&Vec<u8>> = dump
        .iter()
        .filter(|r| r[16] == NL80211_CMD_NEW_WIPHY)
        .collect();
    if wiphys.len() != 1 || find_attr(&wiphys[0][20..], NL80211_ATTR_WIPHY) != find_attr(wiphy, 1) {
        return TestResult::Fail("GET_WIPHY dump not filtered to the ifindex's wiphy");
    }
    if send(
        NL80211_CMD_GET_WIPHY,
        DUMP,
        &ifindex_attr(0x7fff_0000),
        nobody,
    ) != Err(ENODEV)
    {
        return TestResult::Fail("GET_WIPHY dump of a missing netdev was not ENODEV");
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
    // nl80211_trigger_scan: probe IEs up to the advertised
    // NL80211_ATTR_MAX_SCAN_IE_LEN (512) reach the driver; longer is -EINVAL.
    let mut probe_ies = scan.clone();
    push_attr(&mut probe_ies, 42, &[127, 1, 0]);
    let mut oversized_ies = scan.clone();
    push_attr(&mut oversized_ies, 42, &[0; 513]);
    let carried = matches!(
        parse_operation(SCAN, &attributes(&probe_ies).unwrap(), true, false),
        Ok(Operation::Scan(ref r)) if r.extra_ies == [127, 1, 0]
    );
    // `iw scan duration 50 duration-mandatory`: NL80211_ATTR_MEASUREMENT_DURATION
    // (235, u16 TUs) and the _MANDATORY flag (236, NLA_FLAG).
    let mut timed = scan.clone();
    push_attr(&mut timed, 235, &50u16.to_ne_bytes());
    push_attr(&mut timed, 236, &[]);
    let timed_ok = matches!(
        parse_operation(SCAN, &attributes(&timed).unwrap(), true, false),
        Ok(Operation::Scan(ref r)) if r.duration_tu == Some(50) && r.duration_mandatory
    );
    let mut flag_payload = scan.clone();
    push_attr(&mut flag_payload, 235, &50u16.to_ne_bytes());
    push_attr(&mut flag_payload, 236, &[1]);
    if !timed_ok
        || parse_operation(SCAN, &attributes(&flag_payload).unwrap(), true, false).err()
            != Some(EINVAL)
    {
        return TestResult::Fail("scan MEASUREMENT_DURATION (235/236) not honoured");
    }
    if parse_operation(SCAN, &attributes(&random).unwrap(), true, false).err() != Some(EOPNOTSUPP)
        || !carried
        || parse_operation(SCAN, &attributes(&oversized_ies).unwrap(), true, false).err()
            != Some(EINVAL)
    {
        return TestResult::Fail("scan flag / probe IE errnos");
    }
    let admin = narf_net::kernel_admin(E2E_NAME).unwrap();
    CACHE.lock().retain(|c| c.name != E2E_NAME);
    CACHE.lock().push(Cache {
        name: E2E_NAME.into(),
        ifindex,
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
    // validate_pae_over_nl80211: SOCKET_OWNER first (-EINVAL), then the
    // CONTROL_PORT_OVER_NL80211 ext feature (-EOPNOTSUPP).
    let mut owned_pae = pae_over_nl.clone();
    push_attr(&mut owned_pae, 204, &[]);
    if connect_operation(&no_mask).err() != Some(EINVAL)
        || connect_operation(&ethertype).err() != Some(EINVAL)
        || connect_operation(&pae_over_nl).err() != Some(EINVAL)
        || connect_operation(&owned_pae).err() != Some(EOPNOTSUPP)
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

// ── WPA3-Personal: wpa_supplicant 2.12's SAE-offload CONNECT ─────────────

const SAE_NAME: &str = "wlan-sae";
const SAE_MAC: [u8; 6] = [2, 0x5a, 0x5b, 0x5c, 0x5d, 0x02];
const SAE_SSID: &[u8] = b"narf-sae";
const SAE_PASSWORD: &[u8] = b"correct horse battery";
/// A WPA3-only BSS (SAE, MFPC|MFPR, RSNXE H2E) on channel 1, summarised as
/// WPA3, and a WPA3-Personal transition BSS (PSK + SAE, MFPC) on channel 6,
/// which a scan summary classifies as WPA2.
const WPA3_ONLY: [u8; 6] = [2, 0xb0, 0xb1, 0xb2, 0xb3, 0x01];
const TRANSITION: [u8; 6] = [2, 0xb0, 0xb1, 0xb2, 0xb3, 0x06];

fn sae_bss_ies(bssid: [u8; 6]) -> Vec<u8> {
    use crate::rsn::{self, RsnIe, Suite};
    let mut rsne = RsnIe::wpa2_psk_ccmp();
    let mut ies = alloc::vec![0, SAE_SSID.len() as u8];
    ies.extend_from_slice(SAE_SSID);
    if bssid == WPA3_ONLY {
        rsne.akms = alloc::vec![Suite::standard(rsn::AKM_SAE)];
        rsne.rsn_capabilities = rsn::RSN_CAP_MFP_CAPABLE | rsn::RSN_CAP_MFP_REQUIRED;
    } else {
        rsne.akms = alloc::vec![Suite::standard(rsn::AKM_PSK), Suite::standard(rsn::AKM_SAE)];
        rsne.rsn_capabilities = rsn::RSN_CAP_MFP_CAPABLE;
    }
    let body = rsne.encode_body();
    ies.extend_from_slice(&[48, body.len() as u8]);
    ies.extend_from_slice(&body);
    if bssid == WPA3_ONLY {
        ies.extend_from_slice(&[244, 1, rsn::RSNX_CAP_SAE_H2E]);
    }
    ies
}

/// SAE (hunting-and-pecking, group 19) between the station's password and
/// the AP's: true when both Confirms verify and both derive one PMK.
fn sae_exchange(sta_password: &[u8], bssid: [u8; 6]) -> bool {
    use crate::sae::SaeSession;
    let mut sta = SaeSession::new_hunt_and_peck(sta_password, SAE_MAC, bssid);
    let mut ap = SaeSession::new_hunt_and_peck(SAE_PASSWORD, bssid, SAE_MAC);
    let (Ok(sta_commit), Ok(ap_commit)) = (sta.try_build_commit(), ap.try_build_commit()) else {
        return false;
    };
    if sta.on_commit(&ap_commit).is_err() || ap.on_commit(&sta_commit).is_err() {
        return false;
    }
    let (sta_confirm, ap_confirm) = (sta.build_confirm(), ap.build_confirm());
    ap.on_confirm(&sta_confirm).is_ok()
        && sta.on_confirm(&ap_confirm).is_ok()
        && sta.pmk().is_some()
        && sta.pmk() == ap.pmk()
}

/// A full-offload SAE station (the MT7921/MT7922 shape): SAE, the 4-way
/// handshake and PMF run in the driver from the password in CONNECT.
struct SaeStub {
    rx: IrqSafeSpinLock<Option<narf_ipc::Consumer<narf_net::Frame, { narf_net::RX_RING_N }>>>,
    tx: IrqSafeSpinLock<Option<narf_ipc::Producer<narf_net::Frame, { narf_net::TX_RING_N }>>>,
    connected: IrqSafeSpinLock<Option<[u8; 6]>>,
}
impl narf_net::Interface for SaeStub {
    fn name(&self) -> &str {
        SAE_NAME
    }
    fn mac(&self) -> [u8; 6] {
        SAE_MAC
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
impl crate::WirelessNetIface for SaeStub {
    fn max_scan_ssids(&self) -> u8 {
        16
    }
    fn supports_handshake_offload(&self) -> bool {
        true
    }
    fn supports_sae_offload(&self) -> bool {
        true
    }
    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        [WPA3_ONLY, TRANSITION]
            .contains(&bssid)
            .then(|| sae_bss_ies(bssid))
    }
    fn get_wireless_info(&self) -> crate::WirelessIfaceInfo {
        crate::WirelessIfaceInfo {
            base_name: SAE_NAME.into(),
            base_mac: SAE_MAC,
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
        let bss = |bssid, channel: u32, security| crate::BssInfo {
            bssid,
            ssid: SAE_SSID.to_vec(),
            frequency_mhz: 2407 + 5 * channel,
            channel,
            rssi: -50,
            security,
        };
        Ok(alloc::vec![
            bss(WPA3_ONLY, 1, crate::scan::BssSecurity::Wpa3),
            bss(TRANSITION, 6, crate::scan::BssSecurity::Wpa2),
        ])
    }
    async fn associate(&self, req: crate::AssociateRequest) -> Result<(), crate::WirelessError> {
        use crate::association::{validate_sme_ies_for, SmeRsna};
        let crate::SecurityConfig::Wpa3 { password } = &req.security else {
            return Err(crate::WirelessError::InvalidArgs);
        };
        // The native owner's admission of the supplicant's elements.
        if validate_sme_ies_for(&req.ie, SmeRsna::Wpa3Sae).is_err() {
            return Err(crate::WirelessError::NotSupported);
        }
        if ![WPA3_ONLY, TRANSITION].contains(&req.bssid) || !sae_exchange(password, req.bssid) {
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

/// wpa_supplicant 2.12's CONNECT for a NetworkManager `key-mgmt=sae`
/// profile on a SAE-offload wiphy (`wpa_driver_nl80211_try_connect`):
/// NL80211_WPA_VERSION_3, AKM SAE, MFP required, SAE_PWE both, the password
/// and auth type SAE. Without WPA_DRIVER_FLAGS_BSS_SELECTION the supplicant
/// names the BSS it selected (MAC + WIPHY_FREQ) beside the hints.
fn wpa_supplicant_sae_connect(ifindex: u32, bssid: [u8; 6], freq: u32, password: &[u8]) -> Vec<u8> {
    let mut a = ifindex_attr(ifindex);
    push_attr(&mut a, 204, &[]); // IFACE_SOCKET_OWNER
    push_attr(&mut a, 6, &bssid); // MAC
    push_attr(&mut a, 200, &bssid); // MAC_HINT
    push_attr(&mut a, 38, &freq.to_ne_bytes()); // WIPHY_FREQ
    push_attr(&mut a, 201, &freq.to_ne_bytes()); // WIPHY_FREQ_HINT
    push_attr(&mut a, 52, SAE_SSID);
    let mut ie = alloc::vec![
        48, 26, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 8,
        0xcc, 0x00, 0, 0, 0x00, 0x0f, 0xac, 6,
    ];
    ie.extend_from_slice(&[127, 10, 0x04, 0, 0x08, 0, 0, 0, 0, 0x40, 0, 0x20]);
    ie.extend_from_slice(&[244, 1, 0x20]);
    push_attr(&mut a, 42, &ie);
    push_attr(&mut a, 75, &4u32.to_ne_bytes()); // NL80211_WPA_VERSION_3
    push_attr(&mut a, 73, &0x000fac04u32.to_ne_bytes());
    push_attr(&mut a, 74, &0x000fac04u32.to_ne_bytes());
    push_attr(&mut a, 76, &0x000fac08u32.to_ne_bytes()); // AKM SAE
    push_attr(&mut a, 68, &[]); // CONTROL_PORT
    push_attr(&mut a, 102, &0x888eu16.to_ne_bytes());
    push_attr(&mut a, 315, &[]); // MLO_SUPPORT
    push_attr(&mut a, 66, &1u32.to_ne_bytes()); // NL80211_MFP_REQUIRED
    push_attr(&mut a, 298, &[2]); // SAE_PWE: both
    push_attr(&mut a, 277, password); // SAE_PASSWORD
    push_attr(&mut a, 53, &4u32.to_ne_bytes()); // NL80211_AUTHTYPE_SAE
    a
}

/// wpa_supplicant 2.12 against a full-offload SAE station: GET_WIPHY offers
/// SAE_OFFLOAD, the SAE CONNECT (WPA version 3, password) reaches the driver
/// for a WPA3-only and a transition-mode BSS, the driver's SAE exchange
/// succeeds, and nl80211 reports CONNECT(0) then PORT_AUTHORIZED. A wrong
/// password fails SAE and is never authorized.
fn smoke_nl80211_wpa_supplicant_wpa3_sae_offload_end_to_end() -> TestResult {
    register();
    struct Cleanup(Option<fn(u64, u32, &[u8])>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if let Some(previous) = self.0 {
                install_event_sink(previous);
            }
            CACHE.lock().retain(|c| c.name != SAE_NAME);
        }
    }
    let _cleanup = Cleanup(install_event_sink(capture));
    let iface: Arc<dyn crate::WirelessNetIface> = Arc::new(SaeStub {
        rx: IrqSafeSpinLock::new(None),
        tx: IrqSafeSpinLock::new(None),
        connected: IrqSafeSpinLock::new(None),
    });
    narf_net::iface::register(SAE_NAME, SAE_MAC, |_, _| Ok(()));
    crate::registry::register(iface.clone());
    let Some(ifindex) = narf_net::netlink_route::ifindex_for_name(SAE_NAME) else {
        return TestResult::Fail("SAE stub has no ifindex");
    };
    let nobody = RequestContext::default();
    // GET_WIPHY: 4WAY_HANDSHAKE_STA_PSK (15) and SAE_OFFLOAD (38), without
    // which wpa_supplicant drops SAE from its AKM selection.
    let mut attrs = ifindex_attr(ifindex);
    push_attr(&mut attrs, 174, &[]);
    let Ok(replies) = send(NL80211_CMD_GET_WIPHY, 5, &attrs, nobody) else {
        return TestResult::Fail("GET_WIPHY by ifindex failed");
    };
    let bit = |ext: &[u8], n: usize| ext.get(n / 8).is_some_and(|b| b & (1 << (n % 8)) != 0);
    if !find_attr(&replies[0][20..], 217).is_some_and(|ext| bit(ext, 15) && bit(ext, 38)) {
        return TestResult::Fail("GET_WIPHY lacks 4WAY_HANDSHAKE_STA_PSK / SAE_OFFLOAD");
    }

    let admin = narf_net::kernel_admin(SAE_NAME).unwrap();
    CACHE.lock().retain(|c| c.name != SAE_NAME);
    CACHE.lock().push(Cache {
        name: SAE_NAME.into(),
        ifindex,
        namespace: 0,
        busy: true,
        results: Vec::new(),
    });
    let mut scan = ifindex_attr(ifindex);
    let mut ssids = Vec::new();
    push_attr(&mut ssids, 1, &[]);
    push_attr(&mut scan, 45 | NLA_F_NESTED, &ssids);
    let Ok(Operation::Scan(request)) =
        parse_operation(SCAN, &attributes(&scan).unwrap(), true, true)
    else {
        return TestResult::Fail("wildcard TRIGGER_SCAN refused");
    };
    narf_scheduler::block_on_spin(execute(
        iface.clone(),
        admin.clone(),
        0,
        ifindex,
        Operation::Scan(request),
    ));
    let caps = ConnectCaps::of(iface.as_ref());
    let parse =
        |bytes: &[u8]| attributes(bytes).and_then(|a| parse_operation_caps(CONNECT, &a, caps, 0));
    for (bssid, freq) in [(WPA3_ONLY, 2412), (TRANSITION, 2437)] {
        let operation = match parse(&wpa_supplicant_sae_connect(
            ifindex,
            bssid,
            freq,
            SAE_PASSWORD,
        )) {
            Ok(
                operation @ Operation::Connect {
                    cred: Credential::Sae(_),
                    ..
                },
            ) => operation,
            Ok(_) => return TestResult::Fail("SAE CONNECT did not decode to the SAE path"),
            Err(_) => return TestResult::Fail("wpa_supplicant's SAE-offload CONNECT refused"),
        };
        EVENTS.lock().clear();
        narf_scheduler::block_on_spin(execute(iface.clone(), admin.clone(), 0, ifindex, operation));
        let events: Vec<(u32, Vec<u8>)> = EVENTS.lock().clone();
        let connect_at = events.iter().position(|(g, m)| {
            *g == 19
                && m[16] == CONNECT
                && find_attr(&m[20..], 72) == Some(&0u16.to_ne_bytes()[..])
                && find_attr(&m[20..], 6) == Some(&bssid[..])
        });
        let authorized_at = events.iter().position(|(g, m)| {
            *g == 19 && m[16] == PORT_AUTHORIZED && find_attr(&m[20..], 6) == Some(&bssid[..])
        });
        match (connect_at, authorized_at) {
            (Some(c), Some(a)) if c < a => {}
            _ if bssid == WPA3_ONLY => {
                return TestResult::Fail(
                    "WPA3-only SAE connect: no CONNECT(0) then PORT_AUTHORIZED",
                )
            }
            _ => {
                return TestResult::Fail(
                    "transition SAE connect: no CONNECT(0) then PORT_AUTHORIZED",
                )
            }
        }
        if iface.connected_bssid() != Some(bssid) {
            return TestResult::Fail("SAE connect associated a different BSS");
        }
        narf_scheduler::block_on_spin(execute(
            iface.clone(),
            admin.clone(),
            0,
            ifindex,
            Operation::Disconnect,
        ));
    }
    // A wrong password fails SAE: CONNECT reports failure, never authorized.
    let Ok(bad) = parse(&wpa_supplicant_sae_connect(
        ifindex,
        TRANSITION,
        2437,
        b"wrong horse",
    )) else {
        return TestResult::Fail("wrong-password SAE CONNECT refused at parse");
    };
    EVENTS.lock().clear();
    narf_scheduler::block_on_spin(execute(iface.clone(), admin, 0, ifindex, bad));
    let events = EVENTS.lock().clone();
    if !events
        .iter()
        .any(|(_, m)| m[16] == CONNECT && find_attr(&m[20..], 72) != Some(&0u16.to_ne_bytes()[..]))
        || events.iter().any(|(_, m)| m[16] == PORT_AUTHORIZED)
        || iface.connected_bssid().is_some()
    {
        return TestResult::Fail("wrong SAE password was not a failed, unauthorized connect");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/nl80211",
    smoke_nl80211_wpa_supplicant_wpa3_sae_offload_end_to_end
);

static RFKILL_HANDLES: IrqSafeSpinLock<Vec<String>> = IrqSafeSpinLock::new(Vec::new());
fn rfkill_register(name: &str) -> usize {
    let mut names = RFKILL_HANDLES.lock();
    names.push(name.into());
    names.len() - 1
}
fn rfkill_unregister(_: usize) {}

/// The SAE station's wiphy is one rfkill radio. Soft-blocked, the
/// supplicant's CONNECT and TRIGGER_SCAN are -ERFKILL (its interfaces are
/// shut down) while DISCONNECT still reaches the driver; cleared, they are
/// admitted again.
fn smoke_nl80211_rfkill_blocked_wiphy_refuses_scan_and_connect() -> TestResult {
    register();
    crate::rfkill::__test_reset();
    RFKILL_HANDLES.lock().clear();
    let iface: Arc<dyn crate::WirelessNetIface> = Arc::new(SaeStub {
        rx: IrqSafeSpinLock::new(None),
        tx: IrqSafeSpinLock::new(None),
        connected: IrqSafeSpinLock::new(None),
    });
    narf_net::iface::register(SAE_NAME, SAE_MAC, |_, _| Ok(()));
    crate::registry::register(iface.clone());
    crate::rfkill::install(crate::rfkill::Backend {
        register: rfkill_register,
        unregister: rfkill_unregister,
    });
    let Some(ifindex) = narf_net::netlink_route::ifindex_for_name(SAE_NAME) else {
        return TestResult::Fail("SAE stub has no ifindex");
    };
    let root = RequestContext {
        init_net_admin: true,
        net_admin: true,
        ..RequestContext::default()
    };
    let Some(handle) = RFKILL_HANDLES
        .lock()
        .iter()
        .position(|name| name.starts_with("phy"))
    else {
        return TestResult::Fail("wiphy not registered as an rfkill radio");
    };
    let mut scan = ifindex_attr(ifindex);
    let mut ssids = Vec::new();
    push_attr(&mut ssids, 1, &[]);
    push_attr(&mut scan, 45 | NLA_F_NESTED, &ssids);
    let connect = wpa_supplicant_sae_connect(ifindex, WPA3_ONLY, 2412, SAE_PASSWORD);
    const ERFKILL: i32 = 132;
    crate::rfkill::set_soft_blocked(handle, true);
    let blocked = send(CONNECT, 5, &connect, root) == Err(ERFKILL)
        && send(SCAN, 5, &scan, root) == Err(ERFKILL)
        && send(DISCONNECT, 5, &ifindex_attr(ifindex), root) != Err(ERFKILL);
    crate::rfkill::set_soft_blocked(handle, false);
    let unblocked = send(SCAN, 5, &scan, root) != Err(ERFKILL);
    crate::rfkill::__test_reset();
    CACHE.lock().retain(|c| c.name != SAE_NAME);
    if !blocked {
        return TestResult::Fail("blocked wiphy admitted CONNECT/SCAN, or refused DISCONNECT");
    }
    if !unblocked {
        return TestResult::Fail("cleared rfkill still refuses SCAN");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/nl80211",
    smoke_nl80211_rfkill_blocked_wiphy_refuses_scan_and_connect
);
