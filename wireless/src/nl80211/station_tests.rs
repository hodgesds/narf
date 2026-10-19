//! The external-supplicant station commands against a stub driver:
//! every new command's success path and its Linux errnos, in
//! `nl80211_*`'s check order (`net/wireless/nl80211.c`, `util.c`
//! `cfg80211_validate_key_settings`, mac80211 `cfg.c`).

use super::*;
use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, Ordering};
use narf_ipc::{Consumer, Producer};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};

const NAME: &str = "wlan-ext";
const MAC: [u8; 6] = [2, 0x0e, 0x0e, 0x0e, 0x0e, 0x01];
const AP: [u8; 6] = [2, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1];

#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    AddKey(u8, bool, Option<[u8; 6]>, u32),
    DelKey(u8, bool),
    Authorize(bool),
    Tx([u8; 6], u16, Vec<u8>, bool),
    Ps(bool),
    Rekey([u8; 8], Option<u32>),
    Disassociate,
}

struct ExtStub {
    rx: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
    connected: AtomicBool,
    calls: IrqSafeSpinLock<Vec<Call>>,
}

impl Interface for ExtStub {
    fn name(&self) -> &str {
        NAME
    }
    fn mac(&self) -> [u8; 6] {
        MAC
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx
    }
}

#[async_trait::async_trait]
impl crate::WirelessNetIface for ExtStub {
    fn supports_userspace_mlme(&self) -> bool {
        true
    }
    fn supports_external_supplicant(&self) -> bool {
        true
    }
    fn supports_control_port_tx_status(&self) -> bool {
        true
    }
    fn supports_gtk_rekey_offload(&self) -> bool {
        true
    }
    fn set_gtk_rekey_data(&self, data: crate::GtkRekeyData) -> Result<(), i32> {
        // Test only the non-secret values retained by the driver boundary.
        self.calls
            .lock()
            .push(Call::Rekey(data.replay_counter, data.akm));
        Ok(())
    }
    fn get_wireless_info(&self) -> crate::WirelessIfaceInfo {
        crate::WirelessIfaceInfo {
            base_name: NAME.into(),
            base_mac: MAC,
            bands: Vec::new(),
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
        Ok(Vec::new())
    }
    async fn associate(&self, _: crate::AssociateRequest) -> Result<(), crate::WirelessError> {
        self.connected.store(true, Ordering::SeqCst);
        Ok(())
    }
    async fn disassociate(&self) -> Result<(), crate::WirelessError> {
        self.connected.store(false, Ordering::SeqCst);
        self.calls.lock().push(Call::Disassociate);
        Ok(())
    }
    fn connected_bssid(&self) -> Option<[u8; 6]> {
        self.connected.load(Ordering::SeqCst).then_some(AP)
    }
    async fn set_config(&self, _: crate::WirelessConfig) -> Result<(), crate::WirelessError> {
        Err(crate::WirelessError::NotSupported)
    }
    fn add_key(&self, k: crate::KeyParams) -> Result<(), i32> {
        // A peer that is not the AP: sta_info_get_bss fails.
        if k.peer.is_some_and(|p| p != AP) {
            return Err(ENOENT);
        }
        self.calls
            .lock()
            .push(Call::AddKey(k.idx, k.pairwise, k.peer, k.cipher));
        Ok(())
    }
    fn del_key(&self, idx: u8, pairwise: bool, _: Option<[u8; 6]>) -> Result<(), i32> {
        if idx == 3 {
            return Err(ENOENT); // no such key
        }
        self.calls.lock().push(Call::DelKey(idx, pairwise));
        Ok(())
    }
    fn set_port_authorized(&self, peer: [u8; 6], on: bool) -> Result<(), i32> {
        if peer != AP {
            return Err(ENOENT);
        }
        self.calls.lock().push(Call::Authorize(on));
        Ok(())
    }
    fn tx_control_port(&self, dest: [u8; 6], proto: u16, f: Vec<u8>, ne: bool) -> Result<(), i32> {
        if proto != crate::ETH_P_PAE && proto != crate::ETH_P_PREAUTH {
            return Err(EINVAL);
        }
        self.calls.lock().push(Call::Tx(dest, proto, f, ne));
        Ok(())
    }
    fn power_save_default(&self) -> Option<bool> {
        Some(true)
    }
    fn set_power_save(&self, on: bool) -> Result<(), i32> {
        self.calls.lock().push(Call::Ps(on));
        Ok(())
    }
    fn regulatory_domain(&self) -> Option<crate::RegDomainInfo> {
        Some(crate::RegDomainInfo {
            alpha2: *b"US",
            dfs_region: 1,
            self_managed: true,
            rules: alloc::vec![crate::RegRuleInfo {
                flags: 0,
                start_khz: 2_402_000,
                end_khz: 2_472_000,
                max_bw_khz: 40_000,
                max_antenna_gain_mbi: 0,
                max_eirp_mbm: 3000,
                dfs_cac_ms: 0,
            }],
        })
    }
    fn station_info(&self) -> Option<crate::StationInfo> {
        Some(crate::StationInfo {
            signal_dbm: Some(-42),
            chain_signal_dbm: [Some(-42), Some(-47), None, None, None, None, None, None],
            tx_bitrate: Some(crate::RateInfo {
                bitrate_100kbps: 1300,
                ht_mcs: Some(15),
                width_mhz: 40,
                short_gi: true,
                ..Default::default()
            }),
            rx_bitrate: Some(crate::RateInfo {
                bitrate_100kbps: 153,
                he_mcs: Some((4, 1, 1)),
                he_dcm: true,
                // A 106-tone RU is not a 20/40 MHz channel-width report.
                he_ru_alloc: Some(2),
                width_mhz: 20,
                ..Default::default()
            }),
            rx_packets: Some(17),
            tx_packets: Some(23),
            tx_retries: Some(5),
            tx_failed: Some(2),
            tx_duration_us: Some(0x1_0000_0001),
            rx_duration_us: Some(0x2_0000_0002),
            ..Default::default()
        })
    }
}

struct Rig {
    stub: Arc<ExtStub>,
    ifindex: u32,
}

impl Drop for Rig {
    fn drop(&mut self) {
        crate::registry::unregister(NAME);
        narf_net::iface::unregister(NAME);
        station::clear_owner(NAME);
    }
}

fn rig() -> Result<Rig, &'static str> {
    super::super::register();
    crate::registry::unregister(NAME);
    let stub = Arc::new(ExtStub {
        rx: IrqSafeSpinLock::new(None),
        tx: IrqSafeSpinLock::new(None),
        connected: AtomicBool::new(false),
        calls: IrqSafeSpinLock::new(Vec::new()),
    });
    narf_net::iface::register(NAME, MAC, |_, _| Ok(()));
    crate::registry::register(stub.clone());
    let ifindex = narf_net::netlink_route::ifindex_for_name(NAME).ok_or("ifindex")?;
    Ok(Rig { stub, ifindex })
}

fn ctx(portid: u32) -> RequestContext<'static> {
    RequestContext {
        init_net_admin: true,
        net_admin: true,
        capable: true,
        portid,
        ..RequestContext::default()
    }
}

fn base(r: &Rig) -> Vec<u8> {
    let mut a = Vec::new();
    push_attr(&mut a, 3, &r.ifindex.to_ne_bytes());
    a
}

fn key_nest(fields: &[(u16, &[u8])]) -> Vec<u8> {
    let mut k = Vec::new();
    for (t, v) in fields {
        push_attr(&mut k, *t, v);
    }
    k
}

fn with_key(r: &Rig, fields: &[(u16, &[u8])], mac: Option<&[u8]>) -> Vec<u8> {
    let mut a = base(r);
    push_attr(&mut a, 80 | NLA_F_NESTED, &key_nest(fields));
    if let Some(m) = mac {
        push_attr(&mut a, 6, m);
    }
    a
}

const CCMP: [u8; 4] = 0x000f_ac04u32.to_ne_bytes();
const CMAC: [u8; 4] = 0x000f_ac06u32.to_ne_bytes();
const TKIP: [u8; 4] = 0x000f_ac02u32.to_ne_bytes();

/// `NL80211_CMD_SET_REKEY_OFFLOAD`: exact required nested material, the
/// association/up gates, and pass-through to the driver without exposing the
/// KEK/KCK in the test recorder.
fn smoke_nl80211_gtk_rekey_offload() -> TestResult {
    let Ok(r) = rig() else {
        return TestResult::Fail("rig");
    };
    let kek = [0x11; 16];
    let kck = [0x22; 16];
    let replay = [0, 1, 2, 3, 4, 5, 6, 7];
    let akm = 0x000f_ac02u32;
    let request = |include_kck: bool, counter: &[u8]| {
        let mut nested = Vec::new();
        push_attr(&mut nested, 1, &kek); // KEK
        if include_kck {
            push_attr(&mut nested, 2, &kck); // KCK
        }
        push_attr(&mut nested, 3, counter); // REPLAY_CTR
        push_attr(&mut nested, 4, &akm.to_ne_bytes());
        let mut outer = base(&r);
        push_attr(&mut outer, 122 | NLA_F_NESTED, &nested);
        outer
    };
    let run = |attrs: &[u8]| handle(station::SET_REKEY_OFFLOAD, attrs, false, ctx(0)).map(|_| ());
    if run(&request(true, &replay)) != Err(station::ENETDOWN) {
        return TestResult::Fail("SET_REKEY_OFFLOAD down is ENETDOWN");
    }
    narf_net::iface::set_link_state(NAME, true);
    if run(&request(true, &replay)) != Err(station::ENOTCONN) {
        return TestResult::Fail("SET_REKEY_OFFLOAD disconnected is ENOTCONN");
    }
    r.stub.connected.store(true, Ordering::SeqCst);
    if run(&request(true, &replay)).is_err()
        || *r.stub.calls.lock() != [Call::Rekey(replay, Some(akm))]
    {
        return TestResult::Fail("SET_REKEY_OFFLOAD did not retain rekey state");
    }
    if run(&request(false, &replay)) != Err(EINVAL)
        || run(&request(true, &[0; 7])) != Err(station::ERANGE)
    {
        return TestResult::Fail("SET_REKEY_OFFLOAD nested validation");
    }
    TestResult::Pass
}
kernel_test_in!("wireless/nl80211", smoke_nl80211_gtk_rekey_offload);

fn smoke_nl80211_ext_keys() -> TestResult {
    let Ok(r) = rig() else {
        return TestResult::Fail("rig");
    };
    let k16 = [0x11u8; 16];
    let seq6 = [0u8; 6];
    let ptk = |idx: &[u8], cipher: &[u8], key: &[u8], seq: &[u8]| {
        with_key(&r, &[(1, key), (3, cipher), (4, seq), (2, idx)], Some(&AP))
    };
    let gtk = |idx: &[u8], cipher: &[u8], key: &[u8], seq: &[u8], mac: Option<&[u8]>| {
        with_key(&r, &[(1, key), (3, cipher), (4, seq), (2, idx)], mac)
    };
    let run = |cmd: u8, a: &[u8]| handle(cmd, a, false, ctx(0)).map(|_| ());
    // pre_doit: down -ENETDOWN; not connected -ENOLINK.
    if run(station::NEW_KEY, &ptk(&[0], &CCMP, &k16, &seq6)) != Err(station::ENETDOWN) {
        return TestResult::Fail("NEW_KEY on a down netdev not ENETDOWN");
    }
    narf_net::iface::set_link_state(NAME, true);
    if run(station::NEW_KEY, &ptk(&[0], &CCMP, &k16, &seq6)) != Err(station::ENOLINK) {
        return TestResult::Fail("NEW_KEY while not connected not ENOLINK");
    }
    r.stub.connected.store(true, Ordering::SeqCst);
    // The success paths: PTK, GTK, IGTK.
    if run(station::NEW_KEY, &ptk(&[0], &CCMP, &k16, &seq6)).is_err()
        || run(station::NEW_KEY, &gtk(&[1], &CCMP, &k16, &seq6, None)).is_err()
        || run(station::NEW_KEY, &gtk(&[4], &CMAC, &k16, &seq6, None)).is_err()
    {
        return TestResult::Fail("PTK / GTK / IGTK NEW_KEY rejected");
    }
    if *r.stub.calls.lock()
        != [
            Call::AddKey(0, true, Some(AP), 0x000f_ac04),
            Call::AddKey(1, false, None, 0x000f_ac04),
            Call::AddKey(4, false, None, 0x000f_ac06),
        ]
    {
        return TestResult::Fail("keys not handed to the driver as given");
    }
    // The old (top-level) attributes parse the same.
    let mut old = base(&r);
    push_attr(&mut old, 7, &k16);
    push_attr(&mut old, 9, &CCMP);
    push_attr(&mut old, 8, &[2]);
    if run(station::NEW_KEY, &old).is_err() {
        return TestResult::Fail("old-style NEW_KEY rejected");
    }
    let cases: &[(&str, Vec<u8>, i32)] = &[
        (
            "no key data",
            with_key(&r, &[(3, &CCMP), (2, &[0])], Some(&AP)),
            EINVAL,
        ),
        (
            "KEY_TYPE peerkey",
            with_key(
                &r,
                &[(1, &k16), (3, &CCMP), (2, &[0]), (7, &2u32.to_ne_bytes())],
                Some(&AP),
            ),
            EINVAL,
        ),
        (
            "KEY_TYPE out of range",
            with_key(
                &r,
                &[(1, &k16), (3, &CCMP), (2, &[0]), (7, &3u32.to_ne_bytes())],
                Some(&AP),
            ),
            station::ERANGE,
        ),
        (
            "pairwise without MAC",
            with_key(
                &r,
                &[(1, &k16), (3, &CCMP), (2, &[0]), (7, &1u32.to_ne_bytes())],
                None,
            ),
            EINVAL,
        ),
        (
            "group with MAC",
            with_key(
                &r,
                &[(1, &k16), (3, &CCMP), (2, &[1]), (7, &0u32.to_ne_bytes())],
                Some(&AP),
            ),
            EINVAL,
        ),
        (
            "pairwise index 1 (no Extended Key ID)",
            ptk(&[1], &CCMP, &k16, &seq6),
            EINVAL,
        ),
        ("pairwise index 4", ptk(&[4], &CCMP, &k16, &seq6), EINVAL),
        (
            "group index 6 (no beacon protection)",
            gtk(&[6], &CCMP, &k16, &seq6, None),
            EINVAL,
        ),
        ("IGTK index 3", gtk(&[3], &CMAC, &k16, &seq6, None), EINVAL),
        (
            "CCMP key length",
            ptk(&[0], &CCMP, &[0u8; 15], &seq6),
            EINVAL,
        ),
        ("CCMP RSC length", ptk(&[0], &CCMP, &k16, &[0u8; 5]), EINVAL),
        (
            "TKIP not a wiphy cipher",
            ptk(&[0], &TKIP, &[0u8; 32], &seq6),
            EINVAL,
        ),
        (
            "key longer than WLAN_MAX_KEY_LEN",
            ptk(&[0], &CCMP, &[0u8; 33], &seq6),
            station::ERANGE,
        ),
        (
            "defmgmt + def",
            with_key(
                &r,
                &[(1, &k16), (3, &CMAC), (2, &[4]), (5, &[]), (6, &[])],
                None,
            ),
            EINVAL,
        ),
        (
            "index past 7",
            with_key(&r, &[(1, &k16), (3, &CCMP), (2, &[8])], None),
            EINVAL,
        ),
    ];
    for (what, a, want) in cases {
        if run(station::NEW_KEY, a) != Err(*want) {
            let _ = what;
            return TestResult::Fail("a NEW_KEY negative case returned the wrong errno");
        }
    }
    // Old-style KEY_IDX past 7 is the policy's -ERANGE.
    let mut idx9 = base(&r);
    push_attr(&mut idx9, 7, &k16);
    push_attr(&mut idx9, 9, &CCMP);
    push_attr(&mut idx9, 8, &[9]);
    if run(station::NEW_KEY, &idx9) != Err(station::ERANGE) {
        return TestResult::Fail("old KEY_IDX 9 not ERANGE");
    }
    // An MLO link id on a non-MLO wdev.
    let mut mlo = ptk(&[0], &CCMP, &k16, &seq6);
    push_attr(&mut mlo, 313, &[0]);
    if run(station::NEW_KEY, &mlo) != Err(EINVAL) {
        return TestResult::Fail("NEW_KEY with an MLO link id not EINVAL");
    }
    // The driver's -ENOENT (not the AP) passes through.
    let other = with_key(
        &r,
        &[(1, &k16), (3, &CCMP), (4, &seq6), (2, &[0])],
        Some(&[2, 9, 9, 9, 9, 9]),
    );
    if run(station::NEW_KEY, &other) != Err(ENOENT) {
        return TestResult::Fail("NEW_KEY for another peer not ENOENT");
    }
    // Without CAP_NET_ADMIN (no delegated handle) -EPERM, from the genl
    // layer before any of this.
    let nobody = RequestContext {
        portid: 1,
        ..RequestContext::default()
    };
    if handle(
        station::NEW_KEY,
        &ptk(&[0], &CCMP, &k16, &seq6),
        false,
        nobody,
    )
    .map(|_| ())
        != Err(EPERM)
    {
        return TestResult::Fail("NEW_KEY without authority not EPERM");
    }
    // SET_KEY: default keys only.
    let def = |idx: u8, f: u16| with_key(&r, &[(2, &[idx]), (f, &[])], None);
    if run(station::SET_KEY, &def(1, 5)).is_err() || run(station::SET_KEY, &def(4, 6)).is_err() {
        return TestResult::Fail("SET_KEY default / default-mgmt rejected");
    }
    let mut uni = Vec::new();
    push_attr(&mut uni, 1, &[]);
    let defmgmt_uni = with_key(&r, &[(2, &[4]), (6, &[]), (8 | NLA_F_NESTED, &uni)], None);
    if run(station::SET_KEY, &with_key(&r, &[(5, &[])], None)) != Err(EINVAL)
        || run(station::SET_KEY, &with_key(&r, &[(2, &[1])], None)) != Err(EINVAL)
        || run(station::SET_KEY, &def(4, 5)) != Err(EINVAL)
        || run(station::SET_KEY, &def(3, 6)) != Err(EINVAL)
        || run(station::SET_KEY, &defmgmt_uni) != Err(EINVAL)
        || run(
            station::SET_KEY,
            &with_key(&r, &[(2, &[0]), (9, &[2])], Some(&AP)),
        ) != Err(EINVAL)
    {
        return TestResult::Fail("SET_KEY errnos");
    }
    // DEL_KEY.
    r.stub.calls.lock().clear();
    let del = |idx: u8, mac: Option<&[u8]>| with_key(&r, &[(2, &[idx])], mac);
    if run(station::DEL_KEY, &del(0, Some(&AP))).is_err()
        || run(station::DEL_KEY, &del(1, None)).is_err()
    {
        return TestResult::Fail("DEL_KEY rejected");
    }
    if *r.stub.calls.lock() != [Call::DelKey(0, true), Call::DelKey(1, false)] {
        return TestResult::Fail("DEL_KEY not handed to the driver");
    }
    let group_mac = with_key(&r, &[(2, &[1]), (7, &0u32.to_ne_bytes())], Some(&AP));
    if run(station::DEL_KEY, &del(6, None)) != Err(EINVAL)
        || run(station::DEL_KEY, &del(4, Some(&AP))) != Err(EINVAL)
        || run(station::DEL_KEY, &group_mac) != Err(ENOENT)
        || run(station::DEL_KEY, &del(3, None)) != Err(ENOENT)
    {
        return TestResult::Fail("DEL_KEY errnos");
    }
    r.stub.connected.store(false, Ordering::SeqCst);
    if run(station::DEL_KEY, &del(0, Some(&AP))) != Err(station::ENOLINK) {
        return TestResult::Fail("DEL_KEY while not connected not ENOLINK");
    }
    TestResult::Pass
}
kernel_test_in!("wireless/nl80211", smoke_nl80211_ext_keys);

fn smoke_nl80211_ext_station_pmksa_control_port() -> TestResult {
    let Ok(r) = rig() else {
        return TestResult::Fail("rig");
    };
    narf_net::iface::set_link_state(NAME, true);
    r.stub.connected.store(true, Ordering::SeqCst);
    let run = |cmd: u8, a: &[u8]| handle(cmd, a, false, ctx(0)).map(|_| ());
    let flags2 = |mask: u32, set: u32| {
        let mut a = base(&r);
        push_attr(&mut a, 6, &AP);
        let mut f = mask.to_ne_bytes().to_vec();
        f.extend_from_slice(&set.to_ne_bytes());
        push_attr(&mut a, 67, &f);
        a
    };
    // SET_STATION (AUTHORIZED) on the AP's entry.
    if run(SET_STATION, &flags2(2, 2)).is_err() || run(SET_STATION, &flags2(2, 0)).is_err() {
        return TestResult::Fail("SET_STATION authorize / unauthorize rejected");
    }
    if *r.stub.calls.lock() != [Call::Authorize(true), Call::Authorize(false)] {
        return TestResult::Fail("port authorization not handed to the driver");
    }
    let mut no_mac = base(&r);
    push_attr(&mut no_mac, 67, &[2, 0, 0, 0, 2, 0, 0, 0]);
    let mut other = no_mac.clone();
    push_attr(&mut other, 6, &[2, 3, 3, 3, 3, 3]);
    let mut listen = flags2(2, 2);
    push_attr(&mut listen, 18, &10u16.to_ne_bytes());
    let mut short = base(&r);
    push_attr(&mut short, 6, &AP);
    push_attr(&mut short, 67, &[2, 0, 0, 0]);
    if run(SET_STATION, &no_mac) != Err(EINVAL)
        || run(SET_STATION, &other) != Err(ENOENT)
        || run(SET_STATION, &flags2(2 | 8, 2)) != Err(EINVAL) // + ASSOCIATED
        || run(SET_STATION, &flags2(1, 1)) != Err(EINVAL) // __NL80211_STA_FLAG_INVALID
        || run(SET_STATION, &flags2(1 << 6, 1 << 6)) != Err(EINVAL) // TDLS_PEER
        || run(SET_STATION, &listen) != Err(EINVAL)
        || run(SET_STATION, &short) != Err(station::ERANGE)
    {
        return TestResult::Fail("SET_STATION errnos");
    }
    // PMKSA: argument checks, then mac80211's missing ops.
    let pmksa = |pmkid: Option<&[u8]>, mac: bool| {
        let mut a = base(&r);
        if let Some(p) = pmkid {
            push_attr(&mut a, 85, p);
        }
        if mac {
            push_attr(&mut a, 6, &AP);
        }
        a
    };
    if run(station::SET_PMKSA, &pmksa(None, true)) != Err(EINVAL)
        || run(station::SET_PMKSA, &pmksa(Some(&[0; 8]), true)) != Err(station::ERANGE)
        || run(station::SET_PMKSA, &pmksa(Some(&[0; 16]), false)) != Err(EINVAL)
        || run(station::SET_PMKSA, &pmksa(Some(&[0; 16]), true)) != Err(EOPNOTSUPP)
        || run(station::DEL_PMKSA, &pmksa(Some(&[0; 16]), false)) != Err(EINVAL)
        || run(station::DEL_PMKSA, &pmksa(Some(&[0; 16]), true)) != Err(EOPNOTSUPP)
        || run(station::FLUSH_PMKSA, &base(&r)) != Err(EOPNOTSUPP)
    {
        return TestResult::Fail("PMKSA errnos");
    }
    // CONTROL_PORT_FRAME TX.
    r.stub.calls.lock().clear();
    let cp = |frame: Option<&[u8]>, mac: bool, proto: Option<u16>| {
        let mut a = base(&r);
        if let Some(f) = frame {
            push_attr(&mut a, 51, f);
        }
        if mac {
            push_attr(&mut a, 6, &AP);
        }
        if let Some(p) = proto {
            push_attr(&mut a, 102, &p.to_ne_bytes());
        }
        push_attr(&mut a, 103, &[]);
        a
    };
    let cookie = core::cell::Cell::new(None);
    let with_cookie = RequestContext {
        ack_cookie: Some(&cookie),
        ..ctx(0)
    };
    if handle(
        station::CONTROL_PORT_FRAME,
        &cp(Some(&[1, 3, 0, 0]), true, Some(0x888e)),
        false,
        with_cookie,
    )
    .is_err()
        || cookie.get().is_none()
    {
        return TestResult::Fail("CONTROL_PORT_FRAME TX / cookie");
    }
    if *r.stub.calls.lock() != [Call::Tx(AP, 0x888e, alloc::vec![1, 3, 0, 0], true)] {
        return TestResult::Fail("control-port frame not handed to the driver");
    }
    let mut dont_wait = cp(Some(&[1]), true, Some(0x888e));
    push_attr(&mut dont_wait, 142, &[]);
    let quiet = core::cell::Cell::new(None);
    let qctx = RequestContext {
        ack_cookie: Some(&quiet),
        ..ctx(0)
    };
    if handle(station::CONTROL_PORT_FRAME, &dont_wait, false, qctx).is_err()
        || quiet.get().is_some()
    {
        return TestResult::Fail("DONT_WAIT_FOR_ACK still produced a cookie");
    }
    if run(station::CONTROL_PORT_FRAME, &cp(None, true, Some(0x888e))) != Err(EINVAL)
        || run(
            station::CONTROL_PORT_FRAME,
            &cp(Some(&[1]), false, Some(0x888e)),
        ) != Err(EINVAL)
        || run(station::CONTROL_PORT_FRAME, &cp(Some(&[1]), true, None)) != Err(EINVAL)
        || run(
            station::CONTROL_PORT_FRAME,
            &cp(Some(&[1]), true, Some(0x0800)),
        ) != Err(EINVAL)
    {
        return TestResult::Fail("CONTROL_PORT_FRAME argument errnos");
    }
    r.stub.connected.store(false, Ordering::SeqCst);
    if run(
        station::CONTROL_PORT_FRAME,
        &cp(Some(&[1]), true, Some(0x888e)),
    ) != Err(station::ENOTCONN)
    {
        return TestResult::Fail("CONTROL_PORT_FRAME while not connected not ENOTCONN");
    }
    if run(SET_STATION, &flags2(2, 2)) != Err(ENOENT) {
        return TestResult::Fail("SET_STATION while not associated not ENOENT");
    }
    narf_net::iface::set_link_state(NAME, false);
    if run(
        station::CONTROL_PORT_FRAME,
        &cp(Some(&[1]), true, Some(0x888e)),
    ) != Err(station::ENETDOWN)
    {
        return TestResult::Fail("CONTROL_PORT_FRAME on a down netdev not ENETDOWN");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/nl80211",
    smoke_nl80211_ext_station_pmksa_control_port
);

static CONTROL_PORT_STATUS_EVENTS: IrqSafeSpinLock<Vec<(u64, u32, Vec<u8>)>> =
    IrqSafeSpinLock::new(Vec::new());

fn control_port_status_event(namespace: u64, group: u32, message: &[u8]) {
    CONTROL_PORT_STATUS_EVENTS
        .lock()
        .push((namespace, group, message.to_vec()));
}

/// A requested control-port transmission reports the exact cookie and full
/// Ethernet data frame on the MLME multicast group, exactly like
/// `cfg80211_control_port_tx_status`.
fn smoke_nl80211_control_port_tx_status() -> TestResult {
    use narf_net::netlink_generic::install_event_sink;
    let Ok(r) = rig() else {
        return TestResult::Fail("rig");
    };
    let previous = install_event_sink(control_port_status_event);
    CONTROL_PORT_STATUS_EVENTS.lock().clear();
    let frame = [
        AP[0], AP[1], AP[2], AP[3], AP[4], AP[5], MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5],
        0x88, 0x8e, 1, 3, 0, 95,
    ];
    crate::nl80211::notify_control_port_tx_status(NAME, 0xfeed_babe, &frame, true);
    let events = CONTROL_PORT_STATUS_EVENTS.lock().clone();
    let _ = install_event_sink(previous.unwrap_or(control_port_status_event));
    let good = events.len() == 1 && {
        let (namespace, group, message) = &events[0];
        let attrs = &message[20..];
        *namespace == 0
            && *group == 19
            && message[16] == station::CONTROL_PORT_FRAME_TX_STATUS
            && find_attr(attrs, 1).is_some()
            && find_attr(attrs, 3) == Some(&r.ifindex.to_ne_bytes()[..])
            && find_attr(attrs, 153).is_some()
            && find_attr(attrs, 51) == Some(&frame[..])
            && find_attr(attrs, 88) == Some(&0xfeed_babeu64.to_ne_bytes()[..])
            && find_attr(attrs, 92) == Some(&[][..])
    };
    if good {
        TestResult::Pass
    } else {
        TestResult::Fail("CONTROL_PORT_FRAME_TX_STATUS event layout")
    }
}
kernel_test_in!("wireless/nl80211", smoke_nl80211_control_port_tx_status);

/// A locally detected TKIP Michael failure follows cfg80211's MLME event
/// layout. The target may have stripped the IV, so this form has the saved
/// key index but intentionally no KEY_SEQ/TSC.
fn smoke_nl80211_michael_mic_failure() -> TestResult {
    use narf_net::netlink_generic::install_event_sink;
    let Ok(r) = rig() else {
        return TestResult::Fail("rig");
    };
    let previous = install_event_sink(control_port_status_event);
    CONTROL_PORT_STATUS_EVENTS.lock().clear();
    crate::nl80211::notify_michael_mic_failure(NAME, AP, true, Some(2));
    let events = CONTROL_PORT_STATUS_EVENTS.lock().clone();
    let _ = install_event_sink(previous.unwrap_or(control_port_status_event));
    let good = events.len() == 1 && {
        let (namespace, group, message) = &events[0];
        let attrs = &message[20..];
        *namespace == 0
            && *group == 19
            && message[16] == station::MICHAEL_MIC_FAILURE
            && find_attr(attrs, 1).is_some()
            && find_attr(attrs, 3) == Some(&r.ifindex.to_ne_bytes()[..])
            && find_attr(attrs, 6) == Some(&AP[..])
            && find_attr(attrs, 55) == Some(&0u32.to_ne_bytes()[..])
            && find_attr(attrs, 8) == Some(&[2][..])
            && find_attr(attrs, 10).is_none()
    };
    if good {
        TestResult::Pass
    } else {
        TestResult::Fail("MICHAEL_MIC_FAILURE event layout")
    }
}
kernel_test_in!("wireless/nl80211", smoke_nl80211_michael_mic_failure);

fn smoke_nl80211_ext_power_reg_interface_station() -> TestResult {
    let Ok(r) = rig() else {
        return TestResult::Fail("rig");
    };
    let run = |cmd: u8, a: &[u8]| handle(cmd, a, false, ctx(0));
    // Power save: NEED_NETDEV only (down is fine), wdev->ps default on.
    let get = || {
        run(station::GET_POWER_SAVE, &base(&r)).ok().and_then(|v| {
            v.first()
                .and_then(|g| find_attr(&g.attrs, 93).map(|x| x.to_vec()))
        })
    };
    if get() != Some(1u32.to_ne_bytes().to_vec()) {
        return TestResult::Fail("GET_POWER_SAVE default not enabled");
    }
    let set = |v: u32| {
        let mut a = base(&r);
        push_attr(&mut a, 93, &v.to_ne_bytes());
        run(station::SET_POWER_SAVE, &a).map(|_| ())
    };
    if set(0).is_err() || get() != Some(0u32.to_ne_bytes().to_vec()) || set(0).is_err() {
        return TestResult::Fail("SET_POWER_SAVE disable");
    }
    if *r.stub.calls.lock() != [Call::Ps(false)] {
        return TestResult::Fail("the same state reached the driver again");
    }
    if set(2) != Err(station::ERANGE)
        || run(station::SET_POWER_SAVE, &base(&r)).map(|_| ()) != Err(EINVAL)
    {
        return TestResult::Fail("SET_POWER_SAVE errnos");
    }
    // GET_REG do: the global domain, or the wiphy's own with WIPHY.
    let reg = run(station::GET_REG, &[]).ok();
    let global = reg.as_ref().and_then(|v| v.first());
    if !global.is_some_and(|g| {
        find_attr(&g.attrs, 33) == Some(&b"00\0"[..]) && find_attr(&g.attrs, 34).is_some()
    }) {
        return TestResult::Fail("GET_REG global domain");
    }
    let wiphy = crate::registry::list()
        .iter()
        .position(|i| i.name() == NAME)
        .unwrap_or(0) as u32;
    let mut w = Vec::new();
    push_attr(&mut w, 1, &wiphy.to_ne_bytes());
    let own = run(station::GET_REG, &w).ok();
    let own = own.as_ref().and_then(|v| v.first());
    if !own.is_some_and(|g| {
        find_attr(&g.attrs, 33) == Some(&b"US\0"[..])
            && find_attr(&g.attrs, 1) == Some(&wiphy.to_ne_bytes()[..])
            && find_attr(&g.attrs, 146) == Some(&[1][..])
            && find_attr(&g.attrs, 34)
                .and_then(|rules| find_attr(rules, 0))
                .is_some_and(|rule| find_attr(rule, 6) == Some(&3000u32.to_ne_bytes()[..]))
    }) {
        return TestResult::Fail("GET_REG for the wiphy");
    }
    let mut bad = Vec::new();
    push_attr(&mut bad, 1, &0x7fffu32.to_ne_bytes());
    if run(station::GET_REG, &bad).map(|_| ()) != Err(ENODEV) {
        return TestResult::Fail("GET_REG of a missing wiphy not ENODEV");
    }
    match handle(station::GET_REG, &[], true, ctx(0)) {
        Ok(v)
            if v.len() >= 2
                && v.iter().any(|g| {
                    find_attr(&g.attrs, 216).is_some() && find_attr(&g.attrs, 1).is_some()
                }) => {}
        _ => return TestResult::Fail("GET_REG dump lacks the self-managed wiphy"),
    }
    // GET_INTERFACE carries WDEV = wiphy << 32 | 1.
    let mut i = Vec::new();
    push_attr(&mut i, 3, &r.ifindex.to_ne_bytes());
    let iface = super::super::handle_in(NL80211_CMD_GET_INTERFACE, &i, false, 0).ok();
    if !iface.as_ref().and_then(|v| v.first()).is_some_and(|g| {
        find_attr(&g.attrs, 153) == Some(&(((wiphy as u64) << 32) | 1).to_ne_bytes()[..])
    }) {
        return TestResult::Fail("GET_INTERFACE lacks NL80211_ATTR_WDEV");
    }
    // GET_STATION: the driver's signal, TX rate and completion counters.
    r.stub.connected.store(true, Ordering::SeqCst);
    let mut st = base(&r);
    push_attr(&mut st, 6, &AP);
    let sta = run(GET_STATION, &st).ok();
    let info = sta
        .as_ref()
        .and_then(|v| v.first())
        .and_then(|g| find_attr(&g.attrs, 21 | NLA_F_NESTED).map(|x| x.to_vec()));
    let Some(info) = info else {
        return TestResult::Fail("GET_STATION reply");
    };
    let rate = find_attr(&info, 8 | NLA_F_NESTED);
    let rx_rate = find_attr(&info, 14 | NLA_F_NESTED);
    let chain_signal = find_attr(&info, 25 | NLA_F_NESTED);
    if find_attr(&info, 7) != Some(&[(-42i8) as u8][..])
        || find_attr(&info, 9) != Some(&17u32.to_ne_bytes()[..])
        || find_attr(&info, 10) != Some(&23u32.to_ne_bytes()[..])
        || find_attr(&info, 11) != Some(&5u32.to_ne_bytes()[..])
        || find_attr(&info, 12) != Some(&2u32.to_ne_bytes()[..])
        || find_attr(&info, 39) != Some(&0x1_0000_0001u64.to_ne_bytes()[..])
        || find_attr(&info, 32) != Some(&0x2_0000_0002u64.to_ne_bytes()[..])
        || !chain_signal.is_some_and(|chains| {
            find_attr(chains, 0) == Some(&[(-42i8) as u8][..])
                && find_attr(chains, 1) == Some(&[(-47i8) as u8][..])
                && find_attr(chains, 2).is_none()
        })
        || !rate.is_some_and(|r| {
            find_attr(r, 1) == Some(&1300u16.to_ne_bytes()[..])
                && find_attr(r, 2) == Some(&[15][..])
                && find_attr(r, 3).is_some()
                && find_attr(r, 4).is_some()
        })
        || !rx_rate.is_some_and(|r| {
            find_attr(r, 5) == Some(&153u32.to_ne_bytes()[..])
                && find_attr(r, 13) == Some(&[4][..])
                && find_attr(r, 14) == Some(&[1][..])
                && find_attr(r, 15) == Some(&[1][..])
                && find_attr(r, 16) == Some(&[1][..])
                && find_attr(r, 17) == Some(&[2][..])
                && find_attr(r, 3).is_none()
        })
    {
        return TestResult::Fail("STA_INFO signal / TX/RX bitrate / counters");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/nl80211",
    smoke_nl80211_ext_power_reg_interface_station
);

static UNICAST: IrqSafeSpinLock<Vec<(u32, Vec<u8>)>> = IrqSafeSpinLock::new(Vec::new());
const OWNER: u32 = 0x4242;

fn unicast(_: u64, portid: u32, msg: &[u8]) -> bool {
    if portid != OWNER {
        return false;
    }
    UNICAST.lock().push((portid, msg.to_vec()));
    true
}

/// CONNECT without a PMK on an external-supplicant wiphy decodes to the
/// userspace-supplicant credential; SOCKET_OWNER makes the sender the
/// connection owner: CONTROL_PORT_FRAME RX is unicast to it, another
/// socket's DISCONNECT / ASSOCIATE is -EPERM, and closing the owner
/// (NETLINK_URELEASE) disconnects (`cfg80211_autodisconnect_wk`).
fn smoke_nl80211_ext_connect_owner_release() -> TestResult {
    use narf_net::netlink_generic::install_unicast_sink;
    let Ok(r) = rig() else {
        return TestResult::Fail("rig");
    };
    narf_net::iface::set_link_state(NAME, true);
    let prev = install_unicast_sink(unicast);
    let rsn = crate::rsn::RsnIe::wpa2_psk_ccmp().encode_body();
    let mut ie = alloc::vec![48, rsn.len() as u8];
    ie.extend_from_slice(&rsn);
    let connect = |extra: &[(u16, &[u8])]| {
        let mut a = base(&r);
        push_attr(&mut a, 52, b"ext-net");
        push_attr(&mut a, 42, &ie);
        push_attr(&mut a, 75, &2u32.to_ne_bytes());
        push_attr(&mut a, 73, &CCMP);
        push_attr(&mut a, 74, &CCMP);
        push_attr(&mut a, 76, &0x000f_ac02u32.to_ne_bytes());
        push_attr(&mut a, 68, &[]);
        push_attr(&mut a, 102, &0x888eu16.to_ne_bytes());
        for (k, v) in extra {
            push_attr(&mut a, *k, v);
        }
        a
    };
    let caps = ConnectCaps {
        psk_offload: false,
        sae_offload: false,
        external: true,
        cipher_suites: &[],
        scan_random_mac: false,
        connected: false,
    };
    let parse = |a: &[u8]| parse_operation_caps(CONNECT, &attributes(a).unwrap(), caps, OWNER);
    let ok = matches!(
        parse(&connect(&[(204, &[]), (264, &[])])),
        Ok(Operation::Connect {
            cred: Credential::External(crate::ExternalSecurity {
                control_port: crate::ControlPort {
                    enabled: true,
                    over_nl80211: true,
                    no_preauth: false,
                    ..
                },
                ..
            }),
            owner: Some(OWNER),
            ..
        })
    );
    if !ok {
        let _ = install_unicast_sink(prev.unwrap_or(unicast));
        return TestResult::Fail("external CONNECT not decoded");
    }
    let bad = [
        (parse(&connect(&[(264, &[])])).err(), EINVAL), // no SOCKET_OWNER
        (
            parse(&connect(&[(66, &2u32.to_ne_bytes())])).err(),
            EOPNOTSUPP,
        ), // MFP OPTIONAL
        (parse(&connect(&[(254, &[0u8; 32])])).err(), EINVAL), // PMK, no offload
        (parse(&connect(&[(277, b"pw")])).err(), EINVAL), // SAE password, no offload
        (
            parse(&connect(&[(53, &4u32.to_ne_bytes())])).err(),
            EOPNOTSUPP,
        ), // SAE over CONNECT
    ];
    let mut gcmp = connect(&[]);
    gcmp.clear();
    push_attr(&mut gcmp, 3, &r.ifindex.to_ne_bytes());
    push_attr(&mut gcmp, 52, b"ext-net");
    push_attr(&mut gcmp, 73, &0x000f_ac08u32.to_ne_bytes());
    if bad.iter().any(|(got, want)| *got != Some(*want)) || parse(&gcmp).err() != Some(EINVAL) {
        let _ = install_unicast_sink(prev.unwrap_or(unicast));
        return TestResult::Fail("external CONNECT errnos");
    }
    // The owner: set as nl80211_connect does, then RX unicast to it.
    station::set_owner(NAME, 0, OWNER, Some(AP));
    station::set_control_port(NAME, 0, true);
    r.stub.connected.store(true, Ordering::SeqCst);
    UNICAST.lock().clear();
    if !crate::nl80211::rx_control_port(NAME, AP, 0x888e, &[2, 3, 0, 5], true) {
        let _ = install_unicast_sink(prev.unwrap_or(unicast));
        return TestResult::Fail("control-port RX not delivered to the owner");
    }
    let got = UNICAST.lock().clone();
    let good = got.len() == 1 && {
        let m = &got[0].1[20..];
        got[0].1[16] == station::CONTROL_PORT_FRAME
            && find_attr(m, 6) == Some(&AP[..])
            && find_attr(m, 102) == Some(&0x888eu16.to_ne_bytes()[..])
            && find_attr(m, 103).is_some()
            && find_attr(m, 51) == Some(&[2, 3, 0, 5][..])
            && find_attr(m, 153).is_some()
    };
    if !good || !crate::nl80211::control_port_over_nl80211(NAME) {
        let _ = install_unicast_sink(prev.unwrap_or(unicast));
        return TestResult::Fail("CONTROL_PORT_FRAME event layout");
    }
    // Another socket may not disconnect or associate.
    let mut disc = base(&r);
    push_attr(&mut disc, 54, &3u16.to_ne_bytes());
    let mut zero = base(&r);
    push_attr(&mut zero, 54, &0u16.to_ne_bytes());
    let mut assoc = base(&r);
    push_attr(&mut assoc, 52, b"ext-net");
    if handle(DISCONNECT, &disc, false, ctx(9)).map(|_| ()) != Err(EPERM)
        || handle(ASSOCIATE, &assoc, false, ctx(9)).map(|_| ()) != Err(EPERM)
        || handle(DISCONNECT, &zero, false, ctx(OWNER)).map(|_| ()) != Err(EINVAL)
    {
        let _ = install_unicast_sink(prev.unwrap_or(unicast));
        return TestResult::Fail("connection-owner errnos");
    }
    // Closing another socket changes nothing; closing the owner
    // disconnects.
    narf_scheduler::__reset_queues_for_test();
    narf_net::netlink_generic::notify_release(0, 9);
    narf_scheduler::run_until_empty();
    if r.stub.calls.lock().contains(&Call::Disassociate) {
        let _ = install_unicast_sink(prev.unwrap_or(unicast));
        return TestResult::Fail("an unrelated socket's close disconnected");
    }
    narf_net::netlink_generic::notify_release(0, OWNER);
    narf_scheduler::run_until_empty();
    let _ = install_unicast_sink(prev.unwrap_or(unicast));
    if !r.stub.calls.lock().contains(&Call::Disassociate)
        || station::conn_owner(NAME) != 0
        || crate::nl80211::rx_control_port(NAME, AP, 0x888e, &[1], true)
    {
        return TestResult::Fail("closing the owner socket did not disconnect");
    }
    TestResult::Pass
}
kernel_test_in!("wireless/nl80211", smoke_nl80211_ext_connect_owner_release);
