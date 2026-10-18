//! ath11k station mac layer offline tests.
//!
//! A scripted fake firmware ([`World`]) sits behind [`FakeWmi`] /
//! [`FakeDp`]: it records every WMI command, answers the ones Linux
//! waits for (VDEV_START_RESP, PEER_ASSOC_CONF, INSTALL_KEY_COMPLETE,
//! scan events, MGMT_TX_COMPLETION, …), plays an access point for
//! Authentication / Association and runs a real WPA2-PSK authenticator
//! (PTK derived with `narf_wireless::eapol::derive_ptk`, MICs and the
//! AES-wrapped GTK verified both ways).
//!
//! Oracles: every expected WMI command is built with the `wmi.rs`
//! encoders (byte-pinned to Linux in `wmi_tests.rs`) from parameter
//! values derived by hand from Linux `ath11k/mac.c`, `reg.c` and
//! mac80211 — each value's origin is commented. The 802.11 frames are
//! literal bytes written out from mac80211's field order.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
use narf_wireless::eapol::{self, HmacPrimitive, KeyFrame};
use narf_wireless::{AssociateRequest, ScanRequest, SecurityConfig};

use super::mac::{self, *};
use super::mac_frame::{self as frame, Band};
use super::mac_peer::{self as peer, ChanDef, StaBw, Width};
use super::mac_reg::{self as reg, chan_flag, fw_flag, Wiphy};
use super::wmi::*;

type R = Result<(), &'static str>;

fn run(f: impl FnOnce() -> R) -> TestResult {
    match f() {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}

macro_rules! ensure {
    ($c:expr, $m:expr) => {
        if !$c {
            return Err($m);
        }
    };
}

/// Drive a future whose waits are all immediately ready.
fn block<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..16 {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
    panic!("mac future did not complete");
}

/// Run `f` with the Wi-Fi diag latch cleared; return what it latched
/// and restore the previous diag state.
fn latched<T>(f: impl FnOnce() -> T) -> (T, u32, u32) {
    use narf_memory::diag;
    let s = diag::snapshot();
    diag::__reset_for_test();
    let v = f();
    let got = diag::snapshot();
    diag::__reset_for_test();
    diag::set_phase(s.phase);
    diag::set_heap_kb(s.heap_used_kb, s.heap_total_kb);
    if s.first_pf_seen {
        diag::note_pf(s.first_pf_cr2, s.first_pf_rip);
    }
    if s.panic_latched {
        diag::latch_panic(s.panic_marker);
    }
    diag::set_wifi_stage(s.wifi_stage);
    diag::latch_wifi_error(s.wifi_err, s.wifi_detail);
    (v, got.wifi_err, got.wifi_detail)
}

fn le(ws: &[u32]) -> Vec<u8> {
    ws.iter().flat_map(|w| w.to_le_bytes()).collect()
}

fn tlv(tag: u16, value: &[u8]) -> Vec<u8> {
    let mut v = le(&[((tag as u32) << 16) | value.len() as u32]);
    v.extend_from_slice(value);
    v
}

fn event(id: u32, tlvs: &[Vec<u8>]) -> Vec<u8> {
    let mut v = le(&[id]);
    for t in tlvs {
        v.extend_from_slice(t);
    }
    v
}

fn mac_words(m: &[u8; 6]) -> [u32; 2] {
    [
        u32::from_le_bytes([m[0], m[1], m[2], m[3]]),
        u32::from_le_bytes([m[4], m[5], 0, 0]),
    ]
}

// ── Fixture constants ───────────────────────────────────────────────

pub(super) const OWN: [u8; 6] = [0x00, 0x03, 0x7F, 0x12, 0x34, 0x56];
pub(super) const BSSID: [u8; 6] = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
const BSSID2: [u8; 6] = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x01];
pub(super) const SSID: &[u8] = b"narf-ap";
const PDEV: u32 = 0;
/// `ht_cap_info`: ENABLED | HT20_SGI | DYNAMIC_SMPS | TX_STBC |
/// RX_STBC_1SS | LDPC | HT40_SGI | RX_LDPC (`WMI_HT_CAP_*`).
const HT_CAP_INFO: u32 = 0x185F;
/// `vht_cap`: MAX_MPDU_11454 | 160 MHz | RXLDPC | SGI80 | SGI160 |
/// TXSTBC | RXSTBC_1 | SU_BFER | SU_BFEE | BFEE_STS=3 | SOUND_DIM=1 |
/// MU_BFEE | A-MPDU exponent 7.
const VHT_CAP: u32 = 0x0391_79F6;
const MAX_MSG_LEN: u32 = 2048;

fn svc_map(bits: &[u32]) -> ServiceMap {
    let mut m = ServiceMap::default();
    for &b in bits {
        m.set(b);
    }
    m
}

fn caps(six_ghz: bool, svc: &[u32]) -> DeviceCaps {
    let hal = HalRegCapExt {
        low_2ghz_chan: 2312,
        high_2ghz_chan: 2732,
        low_5ghz_chan: 5160,
        high_5ghz_chan: if six_ghz { 7125 } else { 5920 },
        ..Default::default()
    };
    let band = BandCap {
        ht_cap_info: HT_CAP_INFO,
        ..Default::default()
    };
    DeviceCaps {
        mac_addr: OWN,
        pdev_id: PDEV,
        pdev: PdevCap {
            pdev_id: PDEV,
            supported_bands: WMI_HOST_WLAN_2G_5G_CAP,
            tx_chain_mask: 3,
            rx_chain_mask: 3,
            vht_cap: VHT_CAP,
            band_2g: band,
            band_5g: band,
            ..Default::default()
        },
        hal_reg_cap: hal,
        hal_reg_cap_2g: hal,
        hal_reg_cap_5g: hal,
        svc: svc_map(svc),
        hw_max_tx_power: 30,
        num_radios: 1,
    }
}

fn rrule(start: u16, end: u16, bw: u16, pwr: u8, flags: u16) -> RegRule {
    RegRule {
        start_freq: start,
        end_freq: end,
        max_bw: bw,
        reg_power: pwr,
        ant_gain: 0,
        flags,
        ..Default::default()
    }
}

/// A US-like REG_CHAN_LIST_CC_EXT: 2.4 GHz 2402–2472, 5 GHz U-NII-1/2A
/// (DFS)/2C (DFS)/3, 6 GHz LPI rules (AP and default client differ in
/// power so a STA vdev changes the channel list).
fn us_reg(ext: bool) -> RegInfo {
    let mut r = RegInfo {
        is_ext_reg_event: ext,
        alpha2: *b"US",
        dfs_region: reg::dfs_region::FCC,
        max_bw_2ghz: 40,
        max_bw_5ghz: 160,
        rules_2ghz: vec![rrule(2402, 2472, 40, 30, 0)],
        rules_5ghz: vec![
            rrule(5170, 5250, 80, 23, 0),
            rrule(5250, 5330, 80, 23, fw_flag::RADAR),
            rrule(5490, 5730, 160, 23, fw_flag::RADAR),
            rrule(5735, 5835, 80, 30, 0),
        ],
        ..Default::default()
    };
    if ext {
        r.rules_6ghz_ap[WMI_REG_INDOOR_AP] = vec![rrule(5945, 7125, 160, 24, 0)];
        r.max_bw_6ghz_ap[WMI_REG_INDOOR_AP] = 160;
        r.rules_6ghz_client[WMI_REG_INDOOR_AP][0] = vec![rrule(5945, 7125, 160, 18, 0)];
        r.max_bw_6ghz_client[WMI_REG_INDOOR_AP][0] = 160;
    }
    r
}

// ── Fake firmware + AP ──────────────────────────────────────────────

#[derive(Clone, Debug)]
pub(super) struct FwCfg {
    pub(super) scan_started: bool,
    pub(super) scan_start_failed: bool,
    pub(super) scan_completed: bool,
    /// `None` → no VDEV_START_RESP.
    pub(super) vdev_start_status: Option<u32>,
    pub(super) peer_assoc_conf: bool,
    pub(super) install_key_status: Option<u32>,
    pub(super) peer_map: bool,
    pub(super) mgmt_ack: bool,
    /// `None` → the AP never answers.
    pub(super) auth_status: Option<u16>,
    pub(super) assoc_status: Option<u16>,
    /// Frames (`(channel, snr, frame)`) delivered as MGMT_RX between
    /// STARTED and COMPLETED.
    pub(super) beacons: Vec<(u32, u32, Vec<u8>)>,
    /// Run the WPA2 authenticator after a successful association.
    pub(super) eapol: bool,
    pub(super) send_m1: bool,
    pub(super) bad_m3_mic: bool,
    pub(super) m3_rsn: Option<Vec<u8>>,
}

impl Default for FwCfg {
    fn default() -> Self {
        FwCfg {
            scan_started: true,
            scan_start_failed: false,
            scan_completed: true,
            vdev_start_status: Some(0),
            peer_assoc_conf: true,
            install_key_status: Some(0),
            peer_map: true,
            mgmt_ack: true,
            auth_status: Some(0),
            assoc_status: Some(0),
            beacons: Vec::new(),
            eapol: false,
            send_m1: true,
            bad_m3_mic: false,
            m3_rsn: None,
        }
    }
}

struct HmacSha1;
impl HmacPrimitive for HmacSha1 {
    fn out_len(&self) -> usize {
        20
    }
    fn mac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        narf_crypto::pbkdf2_sha1::hmac_sha1(key, data).to_vec()
    }
}

/// `E_K(block)` via AES-CTR on a zero block (CTR's first keystream
/// block is `E_K(counter)`).
fn aes_encrypt(k: &[u8; 16], block: [u8; 16]) -> [u8; 16] {
    let mut b = [0u8; 16];
    narf_crypto::aes_ctr::ctr_apply(k, block, &mut b);
    b
}

/// RFC 3394 §2.2.1 key wrap (the authenticator side).
fn aes_key_wrap(kek: &[u8; 16], plain: &[u8]) -> Vec<u8> {
    let n = plain.len() / 8;
    let mut a = [0xA6u8; 8];
    let mut r: Vec<[u8; 8]> = plain
        .chunks_exact(8)
        .map(|c| c.try_into().unwrap())
        .collect();
    for j in 0..6u64 {
        for (i, ri) in r.iter_mut().enumerate() {
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&a);
            b[8..].copy_from_slice(ri);
            let e = aes_encrypt(kek, b);
            let t = (n as u64) * j + i as u64 + 1;
            for (x, y) in a.iter_mut().zip(e[..8].iter().zip(t.to_be_bytes().iter())) {
                *x = y.0 ^ y.1;
            }
            ri.copy_from_slice(&e[8..]);
        }
    }
    let mut out = a.to_vec();
    for b in r {
        out.extend_from_slice(&b);
    }
    out
}

pub(super) const PMK: [u8; 32] = [0x5A; 32];
const ANONCE: [u8; 32] = [0x11; 32];
const SNONCE_FILL: u8 = 0x22;
pub(super) const GTK: [u8; 16] = [0x7C; 16];
const GTK_IDX: u8 = 1;

#[derive(Default)]
pub(super) struct Ap {
    pub(super) ptk: Option<eapol::Ptk>,
    pub(super) m2_mic_ok: bool,
    pub(super) m2_rsn_ok: bool,
    pub(super) m4_ok: bool,
}

#[derive(Default)]
pub(super) struct World {
    pub(super) now: u64,
    pub(super) cfg: Option<FwCfg>,
    pub(super) sent: Vec<WmiCmd>,
    pub(super) mgmt: Vec<Vec<u8>>,
    pub(super) events: VecDeque<Vec<u8>>,
    pub(super) next_desc: u32,
    pub(super) done_descs: Vec<u32>,
    pub(super) eapol_rx: VecDeque<Vec<u8>>,
    pub(super) eth_tx: Vec<Vec<u8>>,
    pub(super) ap: Ap,
    pub(super) dp_calls: Vec<&'static str>,
    pub(super) authorized: Option<bool>,
    pub(super) sta_wme: Option<bool>,
    pub(super) pn: Vec<(u32, bool, bool)>,
    /// `(start, tid, buf_size, ssn)` per ampdu_action.
    pub(super) ampdu: Vec<(bool, u8, u16, u16)>,
}

type Shared = Arc<IrqSafeSpinLock<World>>;

struct FakeWmi(Shared);
struct FakeDp(Shared);

pub(super) fn mgmt_rx_event(chan: u32, snr: u32, freq: u32, status: u32, f: &[u8]) -> Vec<u8> {
    let mut hdr = le(&[chan, snr, 0, 0, f.len() as u32, status]);
    hdr.extend_from_slice(&le(&[0, 0, 0, 0, 0, 0, 0, 0, 0, PDEV, freq]));
    let mut fr = f.to_vec();
    while fr.len() % 4 != 0 {
        fr.push(0);
    }
    event(
        WMI_MGMT_RX_EVENTID,
        &[tlv(WMI_TAG_MGMT_RX_HDR, &hdr), tlv(WMI_TAG_ARRAY_BYTE, &fr)],
    )
}

fn scan_ev(ty: u32, reason: u32, vdev: u32) -> Vec<u8> {
    event(
        WMI_SCAN_EVENTID,
        &[tlv(
            WMI_TAG_SCAN_EVENT,
            &le(&[ty, reason, 0, 1, ATH11K_SCAN_ID, vdev, 0]),
        )],
    )
}

fn vdev_peer_ev(id: u32, tag: u16, vdev: u32, m: &[u8; 6]) -> Vec<u8> {
    let w = mac_words(m);
    event(id, &[tlv(tag, &le(&[vdev, w[0], w[1]]))])
}

impl World {
    pub(super) fn cfg(&self) -> FwCfg {
        self.cfg.clone().unwrap_or_default()
    }

    pub(super) fn on_cmd(&mut self, c: &WmiCmd) {
        let cfg = self.cfg();
        let w = |i: usize| {
            u32::from_le_bytes([
                c.buf[4 * i],
                c.buf[4 * i + 1],
                c.buf[4 * i + 2],
                c.buf[4 * i + 3],
            ])
        };
        match c.cmd_id {
            WMI_START_SCAN_CMDID => {
                let vdev = w(3);
                if cfg.scan_start_failed {
                    self.events
                        .push_back(scan_ev(scan_event::START_FAILED, 0, vdev));
                    return;
                }
                if !cfg.scan_started {
                    return;
                }
                self.events.push_back(scan_ev(scan_event::STARTED, 0, vdev));
                for (ch, snr, f) in &cfg.beacons {
                    let freq = frame::channel_to_freq(
                        *ch,
                        if *ch <= 14 { Band::Ghz2 } else { Band::Ghz5 },
                    )
                    .unwrap();
                    self.events.push_back(mgmt_rx_event(*ch, *snr, freq, 0, f));
                }
                if cfg.scan_completed {
                    self.events.push_back(scan_ev(
                        scan_event::COMPLETED,
                        scan_reason::COMPLETED,
                        vdev,
                    ));
                }
            }
            WMI_STOP_SCAN_CMDID => {
                let vdev = w(4);
                self.events
                    .push_back(scan_ev(scan_event::COMPLETED, scan_reason::CANCELLED, vdev));
            }
            WMI_VDEV_START_REQUEST_CMDID => {
                if let Some(st) = cfg.vdev_start_status {
                    self.events.push_back(event(
                        WMI_VDEV_START_RESP_EVENTID,
                        &[tlv(
                            WMI_TAG_VDEV_START_RESPONSE_EVENT,
                            &le(&[w(1), 0, 0, st, 3, 0, 0, 2, 2, 30]),
                        )],
                    ));
                }
            }
            WMI_VDEV_DELETE_CMDID => {
                self.events.push_back(event(
                    WMI_VDEV_DELETE_RESP_EVENTID,
                    &[tlv(WMI_TAG_VDEV_DELETE_RESP_EVENT, &le(&[w(1)]))],
                ));
            }
            WMI_VDEV_STOP_CMDID => {
                self.events.push_back(event(
                    WMI_VDEV_STOPPED_EVENTID,
                    &[tlv(WMI_TAG_VDEV_STOPPED_EVENT, &le(&[w(1)]))],
                ));
            }
            WMI_PEER_ASSOC_CMDID => {
                if cfg.peer_assoc_conf {
                    let m = [c.buf[4], c.buf[5], c.buf[6], c.buf[7], c.buf[8], c.buf[9]];
                    self.events.push_back(vdev_peer_ev(
                        WMI_PEER_ASSOC_CONF_EVENTID,
                        WMI_TAG_PEER_ASSOC_CONF_EVENT,
                        w(3),
                        &m,
                    ));
                }
            }
            WMI_VDEV_INSTALL_KEY_CMDID => {
                if let Some(st) = cfg.install_key_status {
                    let m = [
                        c.buf[8], c.buf[9], c.buf[10], c.buf[11], c.buf[12], c.buf[13],
                    ];
                    let mw = mac_words(&m);
                    self.events.push_back(event(
                        WMI_VDEV_INSTALL_KEY_COMPLETE_EVENTID,
                        &[tlv(
                            WMI_TAG_VDEV_INSTALL_KEY_COMPLETE_EVENT,
                            &le(&[w(1), mw[0], mw[1], w(4), w(5), st]),
                        )],
                    ));
                }
            }
            WMI_PEER_DELETE_CMDID => {
                let m = [
                    c.buf[8], c.buf[9], c.buf[10], c.buf[11], c.buf[12], c.buf[13],
                ];
                self.events.push_back(vdev_peer_ev(
                    WMI_PEER_DELETE_RESP_EVENTID,
                    WMI_TAG_PEER_DELETE_RESP_EVENT,
                    w(1),
                    &m,
                ));
            }
            _ => {}
        }
    }

    fn on_mgmt(&mut self, f: &[u8]) -> u32 {
        let desc = self.next_desc;
        self.next_desc += 1;
        self.on_mgmt_desc(f, desc)
    }

    /// The firmware side of `WMI_MGMT_TX_SEND_CMDID` for buffer `desc`.
    pub(super) fn on_mgmt_desc(&mut self, f: &[u8], desc: u32) -> u32 {
        let cfg = self.cfg();
        self.mgmt.push(f.to_vec());
        self.events.push_back(event(
            WMI_MGMT_TX_COMPLETION_EVENTID,
            &[tlv(
                WMI_TAG_MGMT_TX_COMPL_EVENT,
                &le(&[desc, if cfg.mgmt_ack { 0 } else { 1 }, PDEV, 0, 0]),
            )],
        ));
        let fc = u16::from_le_bytes([f[0], f[1]]);
        match fc & 0xFC {
            frame::stype::AUTH => {
                if let Some(st) = cfg.auth_status {
                    let mut r = frame::mgmt_hdr(frame::stype::AUTH, &OWN, &BSSID, &BSSID);
                    r.extend_from_slice(&[0, 0, 2, 0]);
                    r.extend_from_slice(&st.to_le_bytes());
                    self.events.push_back(mgmt_rx_event(6, 60, 2437, 0, &r));
                }
            }
            frame::stype::ASSOC_REQ => {
                if let Some(st) = cfg.assoc_status {
                    self.events
                        .push_back(mgmt_rx_event(6, 60, 2437, 0, &assoc_resp(st)));
                    if st == 0 && cfg.eapol && cfg.send_m1 {
                        self.eapol_rx.push_back(m1());
                    }
                }
            }
            _ => {}
        }
        desc
    }

    /// The authenticator: M2 → M3, M4 → done.
    pub(super) fn on_eth(&mut self, f: &[u8]) {
        self.eth_tx.push(f.to_vec());
        let cfg = self.cfg();
        let Some((_, pdu)) = frame::parse_eapol_eth(f) else {
            return;
        };
        let Some(k) = KeyFrame::decode(&pdu[4..], 16) else {
            return;
        };
        let mut zeroed = pdu.to_vec();
        zeroed[EAPOL_MIC_OFFSET..EAPOL_MIC_OFFSET + 16].fill(0);
        if k.key_information == 0x010A {
            // M2: derive the PTK from the AP's side.
            let ptk = eapol::derive_ptk(&HmacSha1, &PMK, &BSSID, &OWN, &ANONCE, &k.key_nonce, 16);
            self.ap.m2_mic_ok =
                pdu[EAPOL_MIC_OFFSET..EAPOL_MIC_OFFSET + 16] == eapol_mic(&ptk.kck, &zeroed);
            self.ap.m2_rsn_ok = k.key_data == STA_RSN_IE;
            let rsn = cfg.m3_rsn.clone().unwrap_or_else(|| AP_RSN_IE.to_vec());
            let mut kd = rsn;
            kd.extend_from_slice(&[0xDD, 22, 0x00, 0x0F, 0xAC, 0x01, GTK_IDX, 0x00]);
            kd.extend_from_slice(&GTK);
            // IEEE 802.11 §12.7.2: pad with 0xdd then zeros to 8 bytes.
            if kd.len() % 8 != 0 {
                kd.push(0xDD);
                while kd.len() % 8 != 0 {
                    kd.push(0);
                }
            }
            let mut kek = [0u8; 16];
            kek.copy_from_slice(&ptk.kek);
            let mut m3 = KeyFrame::empty(16);
            m3.key_information = 0x13CA;
            m3.key_length = 16;
            m3.replay_counter = 2;
            m3.key_nonce = ANONCE;
            m3.key_data = aes_key_wrap(&kek, &kd);
            let mut b = m3.into_eapol();
            let mut mic = eapol_mic(&ptk.kck, &b);
            if cfg.bad_m3_mic {
                mic[0] ^= 0x01;
            }
            b[EAPOL_MIC_OFFSET..EAPOL_MIC_OFFSET + 16].copy_from_slice(&mic);
            self.eapol_rx.push_back(frame::eapol_eth(&OWN, &BSSID, &b));
            self.ap.ptk = Some(ptk);
        } else if k.key_information == 0x030A {
            if let Some(ptk) = &self.ap.ptk {
                self.ap.m4_ok = pdu[EAPOL_MIC_OFFSET..EAPOL_MIC_OFFSET + 16]
                    == eapol_mic(&ptk.kck, &zeroed)
                    && k.replay_counter == 2;
            }
        }
    }
}

impl WmiPort for FakeWmi {
    fn send(&self, cmd: WmiCmd) -> impl Future<Output = Result<(), i32>> + Send {
        let mut w = self.0.lock();
        w.on_cmd(&cmd);
        w.sent.push(cmd);
        core::future::ready(Ok(()))
    }
    fn next_event(&self, timeout_ms: u32) -> impl Future<Output = Option<Vec<u8>>> + Send {
        let mut w = self.0.lock();
        let e = w.events.pop_front();
        if e.is_none() {
            w.now += timeout_ms as u64;
        }
        core::future::ready(e)
    }
    fn mgmt_tx(&self, _vdev_id: u32, f: &[u8]) -> impl Future<Output = Result<u32, i32>> + Send {
        let d = self.0.lock().on_mgmt(f);
        core::future::ready(Ok(d))
    }
    fn mgmt_tx_done(&self, desc_id: u32) {
        self.0.lock().done_descs.push(desc_id);
    }
    fn now_ms(&self) -> u64 {
        self.0.lock().now
    }
    fn max_msg_len(&self) -> u32 {
        MAX_MSG_LEN
    }
    fn random_bytes(&self, out: &mut [u8]) {
        out.fill(SNONCE_FILL);
    }
}

impl DataPort for FakeDp {
    fn ppdu_stats_req(&self) -> impl Future<Output = Result<(), i32>> + Send {
        self.0.lock().dp_calls.push("ppdu_stats");
        core::future::ready(Ok(()))
    }
    fn mon_status_default(&self, enable: bool) -> impl Future<Output = Result<(), i32>> + Send {
        self.0
            .lock()
            .dp_calls
            .push(if enable { "mon_on" } else { "mon_off" });
        core::future::ready(Ok(()))
    }
    fn vdev_tx_attach(&self, _vdev_id: u32, _addr: [u8; 6]) {
        self.0.lock().dp_calls.push("vdev_tx_attach");
    }
    fn wait_peer_mapped(
        &self,
        _vdev_id: u32,
        _addr: [u8; 6],
        mapped: bool,
        timeout_ms: u32,
    ) -> impl Future<Output = Result<(), i32>> + Send {
        let mut w = self.0.lock();
        w.dp_calls
            .push(if mapped { "peer_map" } else { "peer_unmap" });
        let ok = !mapped || w.cfg().peer_map;
        if !ok {
            w.now += timeout_ms as u64;
        }
        core::future::ready(if ok { Ok(()) } else { Err(110) })
    }
    fn peer_setup(
        &self,
        _vdev_id: u32,
        _addr: [u8; 6],
    ) -> impl Future<Output = Result<(), i32>> + Send {
        self.0.lock().dp_calls.push("peer_setup");
        core::future::ready(Ok(()))
    }
    fn peer_cleanup(&self, _vdev_id: u32, _addr: [u8; 6]) {
        self.0.lock().dp_calls.push("peer_cleanup");
    }
    fn rx_pn_replay_config(
        &self,
        _vdev_id: u32,
        _addr: [u8; 6],
        cipher: u32,
        pairwise: bool,
        install: bool,
    ) -> impl Future<Output = Result<(), i32>> + Send {
        self.0.lock().pn.push((cipher, pairwise, install));
        core::future::ready(Ok(()))
    }
    fn send_eth(&self, f: &[u8]) -> impl Future<Output = Result<(), i32>> + Send {
        self.0.lock().on_eth(f);
        core::future::ready(Ok(()))
    }
    fn recv_eapol(&self, timeout_ms: u32) -> impl Future<Output = Option<Vec<u8>>> + Send {
        let mut w = self.0.lock();
        let e = w.eapol_rx.pop_front();
        if e.is_none() {
            w.now += timeout_ms as u64;
        }
        core::future::ready(e)
    }
    fn set_authorized(&self, _addr: [u8; 6], authorized: bool) {
        self.0.lock().authorized = Some(authorized);
    }
    fn set_sta_wme(&self, _addr: [u8; 6], wme: bool) {
        self.0.lock().sta_wme = Some(wme);
    }
    fn peer_frags_flush(&self, _vdev_id: u32, _addr: [u8; 6]) {}
    fn ampdu_rx_start(
        &self,
        _vdev_id: u32,
        _addr: [u8; 6],
        tid: u8,
        buf_size: u16,
        ssn: u16,
    ) -> impl Future<Output = Result<(), i32>> + Send {
        self.0.lock().ampdu.push((true, tid, buf_size, ssn));
        core::future::ready(Ok(()))
    }
    fn ampdu_rx_stop(
        &self,
        _vdev_id: u32,
        _addr: [u8; 6],
        tid: u8,
    ) -> impl Future<Output = Result<(), i32>> + Send {
        self.0.lock().ampdu.push((false, tid, 0, 0));
        core::future::ready(Ok(()))
    }
}

type TestMac = Mac<FakeWmi, FakeDp>;

fn new_mac(c: DeviceCaps, reg: Option<&RegInfo>, cfg: FwCfg) -> (TestMac, Shared) {
    let w: Shared = Arc::new(IrqSafeSpinLock::new(World {
        cfg: Some(cfg),
        next_desc: 1,
        ..Default::default()
    }));
    let m = Mac::new(
        FakeWmi(w.clone()),
        FakeDp(w.clone()),
        c,
        MacConfig::wcn6855(),
        reg,
    );
    (m, w)
}

fn set_cfg(w: &Shared, f: impl FnOnce(&mut FwCfg)) {
    let mut g = w.lock();
    let mut c = g.cfg();
    f(&mut c);
    g.cfg = Some(c);
}

fn take_sent(w: &Shared) -> Vec<WmiCmd> {
    core::mem::take(&mut w.lock().sent)
}

/// Compare two command lists; prints the first difference.
fn same_cmds(got: &[WmiCmd], exp: &[WmiCmd]) -> bool {
    use core::fmt::Write as _;
    for (i, e) in exp.iter().enumerate() {
        match got.get(i) {
            Some(g) if g == e => {}
            Some(g) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  mac_tests: cmd #{} differs: got {:#x} {:x?} want {:#x} {:x?}",
                    i,
                    g.cmd_id,
                    &g.buf[..g.buf.len().min(48)],
                    e.cmd_id,
                    &e.buf[..e.buf.len().min(48)]
                );
                return false;
            }
            None => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  mac_tests: missing cmd #{} {:#x}",
                    i,
                    e.cmd_id
                );
                return false;
            }
        }
    }
    if got.len() != exp.len() {
        let _ = writeln!(
            narf_console::Writer,
            "  mac_tests: {} extra cmds, first {:#x}",
            got.len() - exp.len(),
            got[exp.len()].cmd_id
        );
        return false;
    }
    true
}

fn pdev(id: u32, v: u32) -> WmiCmd {
    pdev_set_param_cmd(id, v, PDEV)
}

fn vdev(id: u32, v: u32) -> WmiCmd {
    vdev_set_param_cmd(0, id, v)
}

fn ps(id: u32, v: u32) -> WmiCmd {
    sta_powersave_param_cmd(0, id, v)
}

// ── Frames ──────────────────────────────────────────────────────────

/// AP RSN element: version 1, group CCMP, 1 pairwise CCMP, 1 AKM PSK,
/// RSN capabilities 0x000c (16 GTKSA/PTKSA replay counters).
const AP_RSN_IE: [u8; 22] = [
    0x30, 0x14, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00,
    0x00, 0x0F, 0xAC, 0x02, 0x0C, 0x00,
];
/// Our RSN element (wpa_supplicant, pmf=0): capabilities 0.
const STA_RSN_IE: [u8; 22] = [
    0x30, 0x14, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00,
    0x00, 0x0F, 0xAC, 0x02, 0x00, 0x00,
];
/// AP HT capabilities: cap 0x016e (SUP_WIDTH_20_40 | SM_PS disabled |
/// SGI20 | SGI40 | RX_STBC 1), A-MPDU 0x17 (64K, 8 µs), MCS 0–15,
/// tx_params TX_DEFINED.
fn ap_ht_cap() -> Vec<u8> {
    let mut v = vec![0x2D, 26, 0x6E, 0x01, 0x17, 0xFF, 0xFF];
    v.extend_from_slice(&[0; 8]); // rx_mask[2..10]
    v.extend_from_slice(&[0, 0, 0x01, 0, 0, 0]); // rx_highest, tx_params, reserved
    v.extend_from_slice(&[0; 7]); // ext cap, txbf, asel
    v
}
/// HT operation: primary 6, secondary above + any width.
fn ap_ht_oper(primary: u8, param: u8) -> Vec<u8> {
    let mut v = vec![0x3D, 22, primary, param];
    v.extend_from_slice(&[0; 20]);
    v
}
/// WMM Parameter element: BE aifsn 3 cw a4, BK aifsn 7 cw a4, VI aifsn
/// 2 cw 43 txop 94, VO aifsn 2 cw 32 txop 47.
const AP_WMM: [u8; 26] = [
    0xDD, 0x18, 0x00, 0x50, 0xF2, 0x02, 0x01, 0x01, 0x80, 0x00, 0x03, 0xA4, 0x00, 0x00, 0x27, 0xA4,
    0x00, 0x00, 0x42, 0x43, 0x5E, 0x00, 0x62, 0x32, 0x2F, 0x00,
];

fn rates_ies() -> Vec<u8> {
    vec![
        0x01, 0x08, 0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24, 0x32, 0x04, 0x30, 0x48, 0x60,
        0x6C,
    ]
}

/// A 2.4 GHz WPA2 HT40+ beacon on channel 6.
pub(super) fn beacon(bssid: &[u8; 6], ssid: &[u8], ds: u8, rsn: bool) -> Vec<u8> {
    let mut f = frame::mgmt_hdr(frame::stype::BEACON, &[0xFF; 6], bssid, bssid);
    f.extend_from_slice(&[0x10, 0x32, 0x54, 0x76, 0, 0, 0, 0]); // TSF
    f.extend_from_slice(&100u16.to_le_bytes()); // beacon interval
    let cap: u16 = 0x0421 | if rsn { 0x0010 } else { 0 };
    f.extend_from_slice(&cap.to_le_bytes());
    f.push(0);
    f.push(ssid.len() as u8);
    f.extend_from_slice(ssid);
    f.extend_from_slice(&rates_ies()[..10]);
    f.extend_from_slice(&[0x03, 0x01, ds]);
    f.extend_from_slice(&[0x05, 0x04, 0x00, 0x01, 0x00, 0x00]); // TIM, DTIM period 1
    f.extend_from_slice(&[0x2A, 0x01, 0x00]); // ERP
    if rsn {
        f.extend_from_slice(&AP_RSN_IE);
    }
    f.extend_from_slice(&rates_ies()[10..]);
    f.extend_from_slice(&ap_ht_cap());
    f.extend_from_slice(&ap_ht_oper(ds, 0x05));
    f.extend_from_slice(&AP_WMM);
    f
}

fn probe_resp(da: &[u8; 6], bssid: &[u8; 6], ssid: &[u8]) -> Vec<u8> {
    let mut f = beacon(bssid, ssid, 6, true);
    f[0] = 0x50;
    f[4..10].copy_from_slice(da);
    f
}

/// Association Response: capab 0x0431, status, AID 1 (|0xc000),
/// rates, HT cap / op, WMM param.
fn assoc_resp(status: u16) -> Vec<u8> {
    let mut f = frame::mgmt_hdr(frame::stype::ASSOC_RESP, &OWN, &BSSID, &BSSID);
    f.extend_from_slice(&0x0431u16.to_le_bytes());
    f.extend_from_slice(&status.to_le_bytes());
    f.extend_from_slice(&0xC001u16.to_le_bytes());
    f.extend_from_slice(&rates_ies());
    f.extend_from_slice(&ap_ht_cap());
    f.extend_from_slice(&ap_ht_oper(6, 0x05));
    f.extend_from_slice(&AP_WMM);
    f
}

fn m1() -> Vec<u8> {
    let mut k = KeyFrame::empty(16);
    k.key_information = 0x008A; // ver 2 | pairwise | ack
    k.key_length = 16;
    k.replay_counter = 1;
    k.key_nonce = ANONCE;
    frame::eapol_eth(&OWN, &BSSID, &k.into_eapol())
}

// ── Expected command blocks ─────────────────────────────────────────

/// `ath11k_reg_update_chan_list` channel list for the fixture, built
/// from `mac_reg` (pinned separately by `smoke_ath11k_mac_reg_*`).
fn chan_list_cmds(m: &TestMac) -> Vec<WmiCmd> {
    scan_chan_list_cmds(PDEV, &m.scan_chan_list(), MAX_MSG_LEN).unwrap()
}

/// `ath11k_mac_op_start` for the fixture (SPOOF_MAC service set).
fn exp_start(m: &TestMac, seeds: &[u32; 16]) -> Vec<WmiCmd> {
    let mut v = vec![
        pdev(WMI_PDEV_PARAM_PMF_QOS, 1),
        pdev(WMI_PDEV_PARAM_DYNAMIC_BW, 1),
        scan_prob_req_oui_cmd(&OWN),
        pdev(WMI_PDEV_PARAM_ARP_AC_OVERRIDE, 0),
        dfs_phyerr_offload_enable_cmd(PDEV),
        pdev(WMI_PDEV_PARAM_MESH_MCAST_ENABLE, 1),
        pdev(WMI_PDEV_PARAM_TX_CHAIN_MASK, 3),
        pdev(WMI_PDEV_PARAM_RX_CHAIN_MASK, 3),
    ];
    v.extend(chan_list_cmds(m));
    let th4: [u32; 5] = core::array::from_fn(|i| seeds[i]);
    let th6: [u32; 11] = core::array::from_fn(|i| seeds[5 + i]);
    v.push(pdev_lro_cfg_cmd(PDEV, &th4, &th6));
    v.push(pdev(WMI_PDEV_PARAM_IDLE_PS_CONFIG, 1));
    v
}

const SEEDS: [u32; 16] = [0x2222_2222; 16];

/// `ath11k_mac_op_conf_tx(ac)` ×4 for `q` (AC order VO, VI, BE, BK),
/// starting from `wmm` (WME order BE, BK, VI, VO).
fn exp_conf_tx(q: &[TxQueueParams; 4], wmm: &mut [WmmParamsArg; 4]) -> Vec<WmiCmd> {
    let mut v = Vec::new();
    for (ac, p) in q.iter().enumerate() {
        let wme = [3usize, 2, 0, 1][ac];
        wmm[wme] = WmmParamsArg {
            cwmin: p.cw_min,
            cwmax: p.cw_max,
            aifs: p.aifs,
            txop: p.txop,
            ..wmm[wme]
        };
        v.push(vdev_set_wmm_params_cmd(0, wmm, WMI_WMM_PARAM_TYPE_LEGACY));
        v.push(ps(sta_ps_param::UAPSD, 0));
        v.push(ps(
            sta_ps_param::RX_WAKE_POLICY,
            sta_ps_param::RX_WAKE_POLICY_WAKE,
        ));
    }
    v
}

/// `ath11k_mac_op_add_interface` + mac80211's ERP reset + WMM defaults.
fn exp_add_interface() -> Vec<WmiCmd> {
    let mut v = vec![
        vdev_create_cmd(
            &OWN,
            &VdevCreateParams {
                if_id: 0,
                vdev_type: vdev_type::STA,
                subtype: vdev_subtype::NONE,
                pdev_id: PDEV,
                chains_2g: Chains { tx: 2, rx: 2 },
                chains_5g: Chains { tx: 2, rx: 2 },
                ..Default::default()
            },
        ),
        // ath11k_mac_op_update_vif_offload: frame_mode = NATIVE_WIFI (1)
        vdev(WMI_VDEV_PARAM_TX_ENCAP_TYPE, 1),
        vdev(WMI_VDEV_PARAM_RX_DECAP_TYPE, 1),
        // nss = get_num_chains(cfg_tx_chainmask = 3)
        vdev(WMI_VDEV_PARAM_NSS, 2),
        ps(
            sta_ps_param::RX_WAKE_POLICY,
            sta_ps_param::RX_WAKE_POLICY_WAKE,
        ),
        ps(
            sta_ps_param::TX_WAKE_THRESHOLD,
            sta_ps_param::TX_WAKE_THRESHOLD_ALWAYS,
        ),
        ps(
            sta_ps_param::PSPOLL_COUNT,
            sta_ps_param::PSPOLL_COUNT_NO_MAX,
        ),
        sta_powersave_mode_cmd(0, sta_ps_mode::DISABLED),
        // wiphy->rts_threshold = (u32)-1
        vdev(WMI_VDEV_PARAM_RTS_THRESHOLD, 0xFFFF_FFFF),
        // ieee80211_reset_erp_info: SLOT LONG, PREAMBLE LONG (CTS deferred)
        vdev(WMI_VDEV_PARAM_SLOT_TIME, 1),
        vdev(WMI_VDEV_PARAM_PREAMBLE, 1),
    ];
    // ieee80211_set_wmm_default(link, true, enable_qos = false): every AC
    // cw_min 15, cw_max 1023, aifs 2, txop 0.
    let mut wmm = [WmmParamsArg::default(); 4];
    v.extend(exp_conf_tx(&mac::wmm_default(false, false), &mut wmm));
    v
}

fn started_mac(c: DeviceCaps, reg: Option<&RegInfo>, cfg: FwCfg) -> (TestMac, Shared) {
    let (mut m, w) = new_mac(c, reg, cfg);
    block(m.start()).unwrap();
    block(m.add_interface()).unwrap();
    take_sent(&w);
    (m, w)
}

fn default_caps() -> DeviceCaps {
    caps(
        false,
        &[
            WMI_TLV_SERVICE_SPOOF_MAC_SUPPORT,
            WMI_TLV_SERVICE_11D_OFFLOAD,
        ],
    )
}

// ── Bring-up ────────────────────────────────────────────────────────

fn smoke_ath11k_mac_start_sequence() -> TestResult {
    run(|| {
        let reg = us_reg(false);
        let (mut m, w) = new_mac(default_caps(), Some(&reg), FwCfg::default());
        ensure!(block(m.start()).is_ok(), "start");
        let sent = take_sent(&w);
        ensure!(
            same_cmds(&sent, &exp_start(&m, &SEEDS)),
            "ath11k_mac_op_start command list"
        );
        ensure!(
            w.lock().dp_calls == ["ppdu_stats", "mon_on"],
            "ppdu stats request then monitor-status default, in Linux order"
        );
        // A second start is WARN_ON + -EINVAL.
        let (r, err, _) = latched(|| block(m.start()));
        ensure!(
            r.is_err() && err == step::START_PDEV_PARAM,
            "double start refused"
        );
        // Without SPOOF_MAC_SUPPORT no SCAN_PROB_REQ_OUI.
        let (mut m2, w2) = new_mac(caps(false, &[]), Some(&reg), FwCfg::default());
        block(m2.start()).unwrap();
        let s2 = take_sent(&w2);
        ensure!(
            !s2.iter().any(|c| c.cmd_id == WMI_SCAN_PROB_REQ_OUI_CMDID),
            "OUI only with the spoof-MAC service"
        );
        // The OUI word: 00:03:7f → 0x00037f.
        ensure!(
            scan_prob_req_oui_cmd(&OWN).buf
                == le(&[(WMI_TAG_SCAN_PROB_REQ_OUI_CMD as u32) << 16 | 4, 0x037F]),
            "prob req oui = mac[0]<<16 | mac[1]<<8 | mac[2]"
        );
        // LRO: tlv, lro_enable 0, res 0, th_4[5], th_6[11], pdev_id.
        let l = pdev_lro_cfg_cmd(
            7,
            &[1, 2, 3, 4, 5],
            &[6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        );
        let mut want = vec![((WMI_TAG_LRO_INFO_CMD as u32) << 16) | 76, 0, 0];
        want.extend(1..=16);
        want.push(7);
        ensure!(
            l.cmd_id == WMI_LRO_CONFIG_CMDID && l.buf == le(&want),
            "lro config layout"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_mac_start_sequence);

/// A WMI port that fails one `PDEV_SET_PARAM` id with `-ESHUTDOWN`.
struct Failing(Shared, u32);

impl WmiPort for Failing {
    fn send(&self, cmd: WmiCmd) -> impl Future<Output = Result<(), i32>> + Send {
        let mut g = self.0.lock();
        let fail = cmd.cmd_id == WMI_PDEV_SET_PARAM_CMDID && cmd.buf[8..12] == self.1.to_le_bytes();
        g.sent.push(cmd);
        core::future::ready(if fail { Err(108) } else { Ok(()) })
    }
    fn next_event(&self, t: u32) -> impl Future<Output = Option<Vec<u8>>> + Send {
        self.0.lock().now += t as u64;
        core::future::ready(None)
    }
    fn mgmt_tx(&self, _: u32, _: &[u8]) -> impl Future<Output = Result<u32, i32>> + Send {
        core::future::ready(Err(5))
    }
    fn mgmt_tx_done(&self, _: u32) {}
    fn now_ms(&self) -> u64 {
        self.0.lock().now
    }
    fn max_msg_len(&self) -> u32 {
        MAX_MSG_LEN
    }
    fn random_bytes(&self, out: &mut [u8]) {
        out.fill(0);
    }
}

fn smoke_ath11k_mac_start_failure_latches() -> TestResult {
    run(|| {
        let reg = us_reg(false);
        let world: Shared = Arc::new(IrqSafeSpinLock::new(World::default()));
        let mut mf = Mac::new(
            Failing(world.clone(), WMI_PDEV_PARAM_DYNAMIC_BW),
            FakeDp(world.clone()),
            default_caps(),
            MacConfig::wcn6855(),
            Some(&reg),
        );
        let (r, err, detail) = latched(|| block(mf.start()));
        ensure!(
            r == Err(MacError::new(
                step::START_PDEV_PARAM,
                WMI_PDEV_PARAM_DYNAMIC_BW,
                108
            )),
            "DYNAMIC_BW failure is the error, with the port's errno"
        );
        ensure!(
            err == step::START_PDEV_PARAM && detail == WMI_PDEV_PARAM_DYNAMIC_BW,
            "latched step 150 / param id"
        );
        ensure!(
            world.lock().sent.len() == 2,
            "start stops at the failing command"
        );
        // ath11k_mac_op_start's err path leaves the radio OFF: a retry
        // runs the whole sequence again.
        let (r, _, _) = latched(|| block(mf.start()));
        ensure!(
            r.is_err() && world.lock().sent.len() == 4,
            "retried from the top"
        );
        // The IDLE_PS failure is the last one in the sequence.
        let w2: Shared = Arc::new(IrqSafeSpinLock::new(World::default()));
        let mut m2 = Mac::new(
            Failing(w2.clone(), WMI_PDEV_PARAM_IDLE_PS_CONFIG),
            FakeDp(w2.clone()),
            default_caps(),
            MacConfig::wcn6855(),
            Some(&reg),
        );
        let (r, err, _) = latched(|| block(m2.start()));
        ensure!(
            r.is_err() && err == step::START_PDEV_PARAM,
            "idle ps failure"
        );
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_mac_start_failure_latches
);

// ── Regulatory ──────────────────────────────────────────────────────

fn smoke_ath11k_mac_reg_channels() -> TestResult {
    run(|| {
        let reg = us_reg(false);
        let (m, _) = new_mac(default_caps(), Some(&reg), FwCfg::default());
        let wp = m.wiphy();
        let ch = |f: u32| wp.get(f).copied().unwrap();
        // 2402–2472: ch 1 (2412 ± 10) … ch 11 (2462) fit, ch 12 (2467) does not.
        ensure!(ch(2412).flags & chan_flag::DISABLED == 0, "ch1 enabled");
        ensure!(ch(2462).flags & chan_flag::DISABLED == 0, "ch11 enabled");
        ensure!(ch(2467).flags & chan_flag::DISABLED != 0, "ch12 disabled");
        ensure!(ch(2484).flags & chan_flag::DISABLED != 0, "ch14 disabled");
        // Self-managed: max_power = max_reg_power = rule power.
        ensure!(
            ch(2437).max_power == 30 && ch(2437).max_reg_power == 30,
            "2.4 GHz power 30 dBm"
        );
        ensure!(ch(5180).max_power == 23, "U-NII-1 23 dBm");
        // RADAR → IEEE80211_CHAN_RADAR; FCC no NO_IR.
        ensure!(ch(5260).flags & chan_flag::RADAR != 0, "ch52 DFS");
        ensure!(ch(5500).flags & chan_flag::RADAR != 0, "ch100 DFS");
        ensure!(ch(5180).flags & chan_flag::RADAR == 0, "ch36 not DFS");
        ensure!(
            ch(5845).flags & chan_flag::DISABLED != 0,
            "ch169 disabled (rule ends 5835)"
        );
        ensure!(
            ch(5825).flags & chan_flag::DISABLED == 0,
            "ch165 enabled (5815–5835)"
        );
        // HT40 neighbours: ch 1 has no -20 MHz neighbour; ch 11 no +20 enabled.
        ensure!(
            ch(2412).flags & chan_flag::NO_HT40MINUS != 0,
            "ch1 no HT40-"
        );
        ensure!(ch(2412).flags & chan_flag::NO_HT40PLUS == 0, "ch1 HT40+ ok");
        ensure!(
            ch(2462).flags & chan_flag::NO_HT40PLUS != 0,
            "ch11 no HT40+ (ch15 absent)"
        );
        // 2.4 GHz rule is 40 MHz wide → no 80 MHz; 5 GHz AUTO_BW spans
        // contiguous rules (5170–5330 = 160 MHz) → 80 allowed.
        ensure!(
            ch(2437).flags & chan_flag::NO_80MHZ != 0,
            "2.4 GHz no 80 MHz"
        );
        ensure!(ch(5180).flags & chan_flag::NO_80MHZ == 0, "ch36 80 MHz ok");
        // No 6 GHz band without high_5ghz_chan >= 5925.
        ensure!(!wp.supports_6ghz(), "no 6 GHz band");

        // ath11k_reg_update_chan_list content.
        let list = m.scan_chan_list();
        ensure!(list.len() == 11 + 25, "11 + 25 enabled channels");
        ensure!(
            list[0].mhz == 2412 && list[10].mhz == 2462 && list[11].mhz == 5180,
            "band order"
        );
        let c1 = list[0];
        ensure!(
            c1 == ChannelParam {
                mhz: 2412,
                cfreq1: 2412,
                allow_ht: true,
                allow_vht: true,
                allow_he: true,
                phy_mode: phy_mode::MODE_11G,
                maxpower: 60,
                maxregpower: 60,
                antennamax: 0,
                ..Default::default()
            },
            "2412: HT/VHT/HE allowed, 11G, 2 × 30 dBm"
        );
        let c52 = list.iter().find(|c| c.mhz == 5260).unwrap();
        ensure!(
            c52.dfs_set && c52.is_chan_passive && c52.phy_mode == phy_mode::MODE_11A,
            "DFS → passive"
        );
        ensure!(c52.maxpower == 46 && c52.maxregpower == 46, "2 × 23 dBm");
        // (2048 - 20) / 28 = 72 channels per command → one command.
        ensure!(chan_list_cmds(&m).len() == 1, "single chan list command");
        let split = scan_chan_list_cmds(PDEV, &list, 20 + 28 * 10).unwrap();
        ensure!(
            split.len() == 4,
            "36 channels / 10 per command = 4 commands"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_mac_reg_channels);

fn smoke_ath11k_mac_reg_build_and_intersect() -> TestResult {
    run(|| {
        // ath11k_reg_adjust_bw
        ensure!(reg::adjust_bw(5490, 5590, 160) == 80, "100 MHz → 80");
        ensure!(reg::adjust_bw(5590, 5650, 160) == 40, "60 MHz → 40");
        ensure!(reg::adjust_bw(5650, 5660, 160) == 0, "10 MHz → 0");
        ensure!(reg::adjust_bw(5700, 5650, 160) == 0, "end <= start → 0");
        // ETSI weather radar split: 5490–5710 DFS → 5490–5590 / 5590–5650
        // (CAC 600 s) / 5650–5710.
        let mut info = us_reg(false);
        info.dfs_region = reg::dfs_region::ETSI;
        info.rules_5ghz = vec![rrule(5490, 5710, 160, 27, fw_flag::RADAR)];
        let d = reg::build_regd(&info, reg::VdevKind::NotSta).unwrap();
        ensure!(d.dfs_region == 2, "ETSI → NL80211_DFS_ETSI");
        ensure!(d.rules.len() == 4, "2.4 GHz + three weather-radar pieces");
        let w = &d.rules[1..];
        ensure!(
            (w[0].start, w[0].end, w[0].max_bw) == (5490, 5590, 80)
                && (w[1].start, w[1].end, w[1].max_bw, w[1].dfs_cac_ms)
                    == (5590, 5650, 40, 600_000)
                && (w[2].start, w[2].end, w[2].max_bw) == (5650, 5710, 40),
            "weather radar split ranges"
        );
        ensure!(
            w[0].flags == reg::rrf::AUTO_BW | reg::rrf::DFS,
            "5 GHz rules: AUTO_BW | DFS"
        );
        // NO11AX phy bitmap → NO_HE on every rule.
        let mut nohe = us_reg(false);
        nohe.phybitmap = reg::ATH11K_REG_PHY_BITMAP_NO11AX;
        let d = reg::build_regd(&nohe, reg::VdevKind::NotSta).unwrap();
        ensure!(
            d.rules.iter().all(|r| r.flags & reg::rrf::NO_HE != 0),
            "NO11AX → NO_HE"
        );
        // No rules → no regdomain.
        let empty = RegInfo::default();
        ensure!(
            reg::build_regd(&empty, reg::VdevKind::NotSta).is_none(),
            "no rules → None"
        );
        // ath11k_reg_handle_chan_list: status != PASS → -EINVAL.
        let mut st = reg::RegState::default();
        let mut bad = us_reg(false);
        bad.status_code = 2;
        ensure!(
            st.handle_chan_list(&bad, true, reg::VdevKind::NotSta, 1, 2)
                == Err(reg::RegError::Status(2)),
            "failed country set refused"
        );
        // First → default; same alpha2 again → unchanged; new country →
        // intersected new regd.
        let us = us_reg(false);
        ensure!(
            st.handle_chan_list(&us, true, reg::VdevKind::NotSta, 1, 2)
                == Ok(reg::RegUpdate::Default),
            "default regd"
        );
        ensure!(
            st.handle_chan_list(&us, true, reg::VdevKind::NotSta, 1, 2)
                == Ok(reg::RegUpdate::Unchanged),
            "same alpha2 skipped"
        );
        let mut de = us_reg(false);
        de.alpha2 = *b"DE";
        de.rules_2ghz = vec![rrule(2400, 2483, 40, 20, 0)];
        de.rules_5ghz = vec![rrule(5150, 5250, 80, 23, fw_flag::NO_IR)];
        ensure!(
            st.handle_chan_list(&de, true, reg::VdevKind::NotSta, 1, 2) == Ok(reg::RegUpdate::New),
            "new regd"
        );
        let cur = st.current();
        ensure!(cur.alpha2 == *b"DE", "current = new");
        // Intersection: 2402–2472 ∩ 2400–2483 = 2402–2472 at min(30, 20) dBm.
        ensure!(
            (cur.rules[0].start, cur.rules[0].end, cur.rules[0].max_eirp) == (2402, 2472, 20),
            "2.4 GHz intersected"
        );
        ensure!(
            (cur.rules[1].start, cur.rules[1].end) == (5170, 5250)
                && cur.rules[1].flags & reg::rrf::NO_IR != 0,
            "5 GHz intersected, NO_IR unioned"
        );
        ensure!(cur.rules.len() == 2, "only overlapping pairs");
        // phy id beyond num_radios but < num_rxdma_per_pdev: accepted, dropped.
        let mut phy1 = us_reg(false);
        phy1.phy_id = 1;
        ensure!(
            st.handle_chan_list(&phy1, true, reg::VdevKind::NotSta, 1, 2)
                == Ok(reg::RegUpdate::Unchanged),
            "phy 1 dropped"
        );
        phy1.phy_id = 2;
        ensure!(
            st.handle_chan_list(&phy1, true, reg::VdevKind::NotSta, 1, 2)
                == Err(reg::RegError::BadPhy(2)),
            "phy 2 refused"
        );
        // World regd fallback.
        let (m, _) = new_mac(default_caps(), None, FwCfg::default());
        let wp = m.wiphy();
        ensure!(
            wp.get(2412).unwrap().flags & chan_flag::DISABLED == 0,
            "world: ch1"
        );
        ensure!(
            wp.get(5180).unwrap().flags & chan_flag::NO_IR != 0,
            "world: 5 GHz NO_IR"
        );
        ensure!(
            wp.get(5500).unwrap().flags & chan_flag::DISABLED != 0,
            "world: ch100 off"
        );
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_mac_reg_build_and_intersect
);

fn smoke_ath11k_mac_reg_6ghz_sta_rules() -> TestResult {
    run(|| {
        // With 6 GHz and REG_CC_EXT, the STA vdev re-handles the stored
        // event with client LPI rules (18 dBm vs the AP's 24) and the
        // channel list is sent again.
        let reg = us_reg(true);
        let c = caps(true, &[WMI_TLV_SERVICE_REG_CC_EXT_EVENT_SUPPORT]);
        let (mut m, w) = new_mac(c, Some(&reg), FwCfg::default());
        ensure!(m.wiphy().supports_6ghz(), "6 GHz band registered");
        ensure!(
            m.wiphy().get(5955).unwrap().max_power == 24,
            "AP LPI power before a STA vdev"
        );
        ensure!(
            m.wiphy().get(5935).unwrap().hw_value == 2,
            "6 GHz ch 2 present (last)"
        );
        block(m.start()).unwrap();
        let before = chan_list_cmds(&m);
        take_sent(&w);
        block(m.add_interface()).unwrap();
        ensure!(
            m.wiphy().get(5955).unwrap().max_power == 18,
            "client LPI power after add_interface"
        );
        let sent = take_sent(&w);
        let after = chan_list_cmds(&m);
        ensure!(before != after, "channel list changed");
        ensure!(
            sent.iter()
                .rev()
                .take(after.len())
                .rev()
                .cloned()
                .collect::<Vec<_>>()
                == after,
            "new channel list sent after the interface"
        );
        // PSC: 5975 (ch 5) is PSC, 5955 (ch 1) is not.
        let l = m.scan_chan_list();
        ensure!(
            l.iter().find(|c| c.mhz == 5975).unwrap().psc_channel,
            "ch5 PSC"
        );
        ensure!(
            !l.iter().find(|c| c.mhz == 5955).unwrap().psc_channel,
            "ch1 not PSC"
        );
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_mac_reg_6ghz_sta_rules
);

fn smoke_ath11k_mac_add_interface() -> TestResult {
    run(|| {
        let reg = us_reg(false);
        let (mut m, w) = new_mac(default_caps(), Some(&reg), FwCfg::default());
        block(m.start()).unwrap();
        take_sent(&w);
        ensure!(block(m.add_interface()) == Ok(0), "vdev 0");
        let sent = take_sent(&w);
        ensure!(
            same_cmds(&sent, &exp_add_interface()),
            "add_interface command list"
        );
        ensure!(
            m.state_11d() == State11d::Preparing,
            "11D_OFFLOAD → PREPARING"
        );
        ensure!(
            w.lock().dp_calls.contains(&"vdev_tx_attach"),
            "ath11k_dp_vdev_tx_attach"
        );
        // VDEV_CREATE body: if_id 0, type STA, subtype 0, mac, 2 bands,
        // pdev, mbssid 0/0, then 2 × TXRX_STREAMS(band, 2, 2).
        let vc = &sent[0];
        let mw = mac_words(&OWN);
        let mut want = vec![
            ((WMI_TAG_VDEV_CREATE_CMD as u32) << 16) | 36,
            0,
            2,
            0,
            mw[0],
            mw[1],
            2,
            PDEV,
            0,
            0,
            ((WMI_TAG_ARRAY_STRUCT as u32) << 16) | 32,
        ];
        for band in 0..2 {
            want.extend_from_slice(&[((WMI_TAG_VDEV_TXRX_STREAMS as u32) << 16) | 12, band, 2, 2]);
        }
        ensure!(
            vc.cmd_id == WMI_VDEV_CREATE_CMDID && vc.buf == le(&want),
            "vdev create words"
        );
        // A second interface is refused.
        let (r, err, _) = latched(|| block(m.add_interface()));
        ensure!(
            r.is_err() && err == step::VDEV_CREATE,
            "second vdev refused"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_mac_add_interface);

fn smoke_ath11k_mac_wmm_params_layout() -> TestResult {
    run(|| {
        let ac = [
            WmmParamsArg {
                cwmin: 15,
                cwmax: 1023,
                aifs: 3,
                txop: 0,
                acm: 0,
                no_ack: 0,
            },
            WmmParamsArg {
                cwmin: 15,
                cwmax: 1023,
                aifs: 7,
                txop: 0,
                acm: 1,
                no_ack: 0,
            },
            WmmParamsArg {
                cwmin: 7,
                cwmax: 15,
                aifs: 2,
                txop: 94,
                acm: 0,
                no_ack: 1,
            },
            WmmParamsArg {
                cwmin: 3,
                cwmax: 7,
                aifs: 2,
                txop: 47,
                acm: 0,
                no_ack: 0,
            },
        ];
        let c = vdev_set_wmm_params_cmd(5, &ac, WMI_WMM_PARAM_TYPE_LEGACY);
        let t = WMI_TAG_VDEV_SET_WMM_PARAMS_CMD as u32;
        let mut want = vec![(t << 16) | 120, 5];
        for a in &ac {
            want.extend_from_slice(&[
                (t << 16) | 24,
                a.cwmin as u32,
                a.cwmax as u32,
                a.aifs as u32,
                a.txop as u32,
                a.acm as u32,
                a.no_ack as u32,
            ]);
        }
        want.push(0);
        ensure!(
            c.cmd_id == WMI_VDEV_SET_WMM_PARAMS_CMDID && c.buf == le(&want),
            "wmm params: 124 bytes, per-AC tag quirk"
        );
        // mac80211 QoS defaults (enable_qos, not 11b): VO 3/7/2/47,
        // VI 7/15/2/94, BE 15/1023/3/0, BK 15/1023/7/0.
        let d = mac::wmm_default(true, false);
        ensure!(
            (d[0].cw_min, d[0].cw_max, d[0].aifs, d[0].txop) == (3, 7, 2, 47)
                && (d[1].cw_min, d[1].cw_max, d[1].aifs, d[1].txop) == (7, 15, 2, 94)
                && (d[2].cw_min, d[2].cw_max, d[2].aifs, d[2].txop) == (15, 1023, 3, 0)
                && (d[3].cw_min, d[3].cw_max, d[3].aifs, d[3].txop) == (15, 1023, 7, 0),
            "QoS defaults"
        );
        let b = mac::wmm_default(true, true);
        ensure!(
            (b[0].cw_min, b[0].cw_max, b[0].txop) == (7, 15, 102) && b[2].cw_min == 31,
            "11b defaults"
        );
        // The fixture's WMM element: VO aifsn 2 ecw 2/3 txop 47 …
        let p = frame::WmmParam::parse(&AP_WMM[2..]).unwrap();
        let q = mac::wmm_from_ie(&p);
        ensure!(
            (q[0].cw_min, q[0].cw_max, q[0].aifs, q[0].txop) == (3, 7, 2, 47)
                && (q[1].cw_min, q[1].cw_max, q[1].aifs, q[1].txop) == (7, 15, 2, 94)
                && (q[2].cw_min, q[2].cw_max, q[2].aifs, q[2].txop) == (15, 1023, 3, 0)
                && (q[3].cw_min, q[3].cw_max, q[3].aifs, q[3].txop) == (15, 1023, 7, 0),
            "ACI → AC mapping and ecw2cw"
        );
        // AIFSN below 2 is raised to 2.
        let mut low = p;
        low.ac[0].aci_aifsn = 0x01;
        ensure!(mac::wmm_from_ie(&low)[2].aifs == 2, "aifs < 2 → 2");
        // OBSS spatial reuse: pdev_id never filled.
        let o = obss_spr_cmd(3, 0, 0, 0);
        ensure!(
            o.cmd_id == WMI_PDEV_OBSS_PD_SPATIAL_REUSE_CMDID
                && o.buf
                    == le(&[
                        ((WMI_TAG_OBSS_SPATIAL_REUSE_SET_CMD as u32) << 16) | 20,
                        0,
                        0,
                        0,
                        0,
                        3
                    ]),
            "obss spr layout"
        );
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_mac_wmm_params_layout
);

// ── Scan ────────────────────────────────────────────────────────────

fn all_freqs(m: &TestMac) -> Vec<u32> {
    m.wiphy()
        .iter()
        .filter(|c| c.flags & chan_flag::DISABLED == 0)
        .map(|c| c.center_freq)
        .collect()
}

fn exp_scan_start(m: &TestMac, ssids: &[Vec<u8>], prio_11d: bool, extraie: Vec<u8>) -> WmiCmd {
    let mut a = ScanReqParams::start_scan_init(prio_11d, false);
    a.vdev_id = 0;
    a.scan_id = ATH11K_SCAN_ID;
    a.scan_ctrl_flags |= scan_flag::FILTER_PROBE_REQ;
    if ssids.is_empty() {
        a.scan_ctrl_flags |= scan_flag::PASSIVE;
    } else {
        a.ssids = ssids.to_vec();
        a.extraie = extraie;
    }
    a.chan_list = all_freqs(m);
    scan_start_cmd(&a).unwrap()
}

fn smoke_ath11k_mac_scan_collects() -> TestResult {
    run(|| {
        let reg = us_reg(false);
        let mut cfg = FwCfg::default();
        let mut weak = beacon(&BSSID, SSID, 6, true);
        weak[8] = 0; // unchanged identity
        cfg.beacons = vec![
            (6, 50, beacon(&BSSID, SSID, 6, true)),
            // Same BSS again, weaker: the latest signal wins.
            (6, 40, weak),
            // Heard on ch 5, DS says ch 6: listed on 2437, signal kept.
            (5, 70, beacon(&BSSID, SSID, 6, true)),
            // An open network with a truncated trailing element.
            (1, 30, {
                let mut b = beacon(&BSSID2, b"open", 1, false);
                b.extend_from_slice(&[0xDD, 0x09, 0x00]);
                b
            }),
            // Probe response to another station: ignored.
            (
                6,
                55,
                probe_resp(&[0x02, 9, 9, 9, 9, 9], &[0x02, 7, 7, 7, 7, 7], b"other"),
            ),
            // SSID element longer than 32 bytes: dropped.
            (6, 55, beacon(&[0x02, 8, 8, 8, 8, 8], &[b'x'; 33], 6, false)),
            // DS channel 13 (disabled under US): dropped.
            (11, 55, beacon(&[0x02, 6, 6, 6, 6, 6], b"ch13", 13, false)),
        ];
        let (mut m, w) = started_mac(default_caps(), Some(&reg), cfg);
        let res = block(m.scan(&ScanRequest {
            ssids: Vec::new(),
            channels: Vec::new(),
            active: false,
        }));
        let Ok(res) = res else {
            return Err("scan failed");
        };
        let sent = take_sent(&w);
        // ath11k_mac_op_hw_scan: start_scan_init(PREPARING → MEDIUM),
        // FILTER_PROBE_REQ, PASSIVE, every enabled channel; then
        // ath11k_mac_11d_scan_start (still PREPARING) = 11D_SCAN_START
        // (vdev 0, 600000 ms, 0).
        let want = vec![
            exp_scan_start(&m, &[], true, Vec::new()),
            scan_11d_start_cmd(0, 600_000, 0),
        ];
        ensure!(same_cmds(&sent, &want), "hw_scan command list");
        ensure!(m.state_11d() == State11d::Running, "11d running");
        ensure!(m.scan_state() == ScanState::Idle, "scan finished");
        ensure!(res.len() == 2, "two BSSes");
        let a = res.iter().find(|b| b.bssid == BSSID).unwrap();
        ensure!(a.ssid == SSID && a.channel == 6, "ssid / channel");
        // ATH11K_DEFAULT_NOISE_FLOOR (-95) + snr 40.
        ensure!(a.rssi == -55, "latest same-channel signal (snr 40 - 95)");
        ensure!(
            matches!(a.security, narf_wireless::scan::BssSecurity::Wpa2),
            "RSN PSK → WPA2"
        );
        let o = res.iter().find(|b| b.bssid == BSSID2).unwrap();
        ensure!(o.channel == 1 && o.rssi == -65, "open BSS on ch1");
        ensure!(
            matches!(o.security, narf_wireless::scan::BssSecurity::Open),
            "open"
        );
        let table = m.bss_table();
        let e = table.iter().find(|b| b.bssid == BSSID2).unwrap();
        ensure!(
            !e.parsed().well_formed && e.parsed().ssid.as_deref() == Some(&b"open"[..]),
            "truncated element tolerated"
        );
        // A second, active scan for SSID: probe IEs, MEDIUM no longer.
        let res2 = block(m.scan(&ScanRequest {
            ssids: vec![SSID.to_vec()],
            channels: vec![6],
            active: true,
        }));
        ensure!(res2.is_ok(), "active scan");
        let sent = take_sent(&w);
        ensure!(
            sent.len() == 1 && sent[0].cmd_id == WMI_START_SCAN_CMDID,
            "only START_SCAN (11d running)"
        );
        // Channel list = 2437 only; SSID list; not passive.
        let body = &sent[0].buf;
        let rd = |o: usize| u32::from_le_bytes([body[o], body[o + 1], body[o + 2], body[o + 3]]);
        ensure!(
            rd(16) == scan_priority::LOW,
            "LOW priority after 11d started"
        );
        ensure!(rd(4 + 4 * 14) & scan_flag::PASSIVE == 0, "active");
        ensure!(
            rd(4 + 4 * 16) == 1 && rd(4 + 4 * 18) == 1,
            "one channel, one ssid"
        );
        ensure!(rd(160 + 4) == 2437, "channel 2437");
        // Invalid requests.
        ensure!(
            block(m.scan(&ScanRequest {
                ssids: vec![],
                channels: vec![12],
                active: false
            }))
            .err()
                == Some(narf_wireless::WirelessError::InvalidArgs),
            "disabled channel refused"
        );
        ensure!(
            block(m.scan(&ScanRequest {
                ssids: vec![vec![0; 33]],
                channels: vec![],
                active: true
            }))
            .err()
                == Some(narf_wireless::WirelessError::InvalidArgs),
            "long SSID refused"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_mac_scan_collects);

fn smoke_ath11k_mac_scan_rx_filtering() -> TestResult {
    run(|| {
        // Frames outside a scan are not recorded; CRC / decrypt errors
        // are dropped (ath11k_mgmt_rx_event).
        let reg = us_reg(false);
        let (mut m, w) = started_mac(default_caps(), Some(&reg), FwCfg::default());
        w.lock().events.push_back(mgmt_rx_event(
            6,
            50,
            2437,
            0,
            &beacon(&BSSID, SSID, 6, true),
        ));
        let _ = block(m.poll());
        ensure!(m.bss_table().is_empty(), "no scan → no BSS");
        set_cfg(&w, |c| {
            c.beacons = vec![(6, 50, beacon(&BSSID, SSID, 6, true))];
        });
        // The CRC-error copy goes in before the scan's good one.
        let r = block(async {
            m.handle_event(&mgmt_rx_event(
                6,
                50,
                2437,
                rx_status::ERR_CRC,
                &beacon(&BSSID2, b"crc", 6, false),
            ));
            m.hw_scan(&[], &[2437]).await
        });
        ensure!(
            r.as_ref().map_or(0, |v| v.len()) == 1,
            "one BSS from the good beacon"
        );
        ensure!(
            !m.bss_table().iter().any(|b| b.bssid == BSSID2),
            "CRC error dropped"
        );
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_mac_scan_rx_filtering
);

fn smoke_ath11k_mac_scan_negatives() -> TestResult {
    run(|| {
        let reg = us_reg(false);
        // No STARTED: wait 5 s (11D_OFFLOAD), then STOP_SCAN + -ETIMEDOUT.
        let (mut m, w) = started_mac(
            default_caps(),
            Some(&reg),
            FwCfg {
                scan_started: false,
                ..Default::default()
            },
        );
        let t0 = w.lock().now;
        let (r, err, detail) = latched(|| block(m.hw_scan(&[], &[2412])));
        ensure!(
            r.is_err() && err == step::SCAN_START_TIMEOUT && detail == 5000,
            "start timeout latched (5 s)"
        );
        ensure!(w.lock().now - t0 >= 5000, "waited the Linux timeout");
        let sent = take_sent(&w);
        ensure!(
            sent.iter()
                .any(|c| *c == scan_stop_cmd(0, 0, ATH11K_SCAN_ID, PDEV, ScanCancel::Single)),
            "STOP_SCAN(single, ATH11K_SCAN_ID)"
        );
        ensure!(m.scan_state() == ScanState::Idle, "state reset");
        // START_FAILED → -EINVAL.
        set_cfg(&w, |c| {
            c.scan_started = true;
            c.scan_start_failed = true;
        });
        let (r, err, _) = latched(|| block(m.hw_scan(&[], &[2412])));
        ensure!(
            r.map_err(|e| e.errno) == Err(22) && err == step::SCAN_START_FAILED,
            "start failed → -EINVAL"
        );
        // STARTED but never COMPLETED: timeout work aborts after
        // max_scan_time + 200 ms; STOP_SCAN is answered with CANCELLED.
        set_cfg(&w, |c| {
            c.scan_start_failed = false;
            c.scan_completed = false;
        });
        take_sent(&w);
        let t0 = w.lock().now;
        let (r, err, _) = latched(|| block(m.hw_scan(&[], &[2412])));
        ensure!(
            r.is_ok() && err == step::SCAN_TIMEOUT,
            "scan timeout latched, results still returned"
        );
        ensure!(w.lock().now - t0 >= 20_200, "20 s + 200 ms");
        let sent = take_sent(&w);
        ensure!(
            sent.last().unwrap().cmd_id == WMI_STOP_SCAN_CMDID,
            "abort sends STOP_SCAN"
        );
        ensure!(m.scan_state() == ScanState::Idle, "aborted scan finished");
        // No vdev → refused.
        let (mut m2, _w2) = new_mac(default_caps(), Some(&reg), FwCfg::default());
        let (r, err, _) = latched(|| block(m2.hw_scan(&[], &[2412])));
        ensure!(r.is_err() && err == step::SCAN_BUSY, "no vdev");
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_mac_scan_negatives);

// ── Frames ──────────────────────────────────────────────────────────

/// The Association Request mac80211 sends to the fixture WPA2 AP
/// (`ieee80211_send_assoc` / `ieee80211_add_link_elems`), with the HT
/// capability word `ht_cap`.
fn exp_assoc_req(ht_cap: u16) -> Vec<u8> {
    let mut want = vec![
        0x00, 0x00, 0x00, 0x00, // FC assoc req, duration
        0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, // DA
        0x00, 0x03, 0x7F, 0x12, 0x34, 0x56, // SA
        0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, // BSSID
        0x00, 0x00, // seq
        0x31, 0x04, // ESS | PRIVACY | SHORT_PREAMBLE | SHORT_SLOT (2.4 GHz)
        0x05, 0x00, // listen interval = ATH11K_MAX_HW_LISTEN_INTERVAL
        0x00, 0x07, b'n', b'a', b'r', b'f', b'-', b'a', b'p', // SSID
        // Supported Rates: the 8 first common rates, basic bit clear.
        0x01, 0x08, 0x02, 0x04, 0x0B, 0x16, 0x0C, 0x12, 0x18, 0x24, 0x32, 0x04, 0x30, 0x48, 0x60,
        0x6C, // Extended Supported Rates
    ];
    want.extend_from_slice(&STA_RSN_IE); // before HT (before_ht[])
                                         // HT capabilities: ath11k_create_ht_cap(0x185f) = LDPC | 20/40 |
                                         // SM_PS dynamic (powersave + DYNAMIC_SMPS) | SGI20 | SGI40 |
                                         // TX_STBC | RX_STBC 1 | MAX_AMSDU (vht max mpdu ≠ 0) | DSSSCCK40
                                         // = 0x19e7; A-MPDU 64K / no density; MCS 0–15; TX_DEFINED.
    want.extend_from_slice(&[0x2D, 26]);
    want.extend_from_slice(&ht_cap.to_le_bytes());
    want.extend_from_slice(&[0x03, 0xFF, 0xFF]);
    want.extend_from_slice(&[0; 8]);
    want.extend_from_slice(&[0, 0, 0x01, 0, 0, 0]);
    want.extend_from_slice(&[0; 7]);
    // WMM Information element, QoS info 0 (no U-APSD queues).
    want.extend_from_slice(&[0xDD, 0x07, 0x00, 0x50, 0xF2, 0x02, 0x00, 0x01, 0x00]);
    want
}

fn smoke_ath11k_mac_auth_assoc_frames() -> TestResult {
    run(|| {
        // ieee80211_send_auth, Open System: FC b0 00, duration 0, DA =
        // BSSID, SA = us, BSSID, seq 0, alg 0, transaction 1, status 0.
        let auth = frame::build_auth_open(&OWN, &BSSID);
        let want: [u8; 30] = [
            0xB0, 0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00, 0x03, 0x7F, 0x12,
            0x34, 0x56, 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00,
        ];
        ensure!(auth == want, "auth frame bytes");
        // ieee80211_send_deauth_disassoc: FC c0 00 … reason 3.
        let d = frame::build_deauth(&OWN, &BSSID, 3);
        ensure!(
            d[0] == 0xC0 && d[1] == 0 && d[24..] == [3, 0] && d.len() == 26,
            "deauth frame"
        );

        // Association Request for the fixture WPA2 HT40 AP, as mac80211
        // builds it (ieee80211_send_assoc / ieee80211_add_link_elems).
        let reg = us_reg(false);
        let cfg = FwCfg {
            beacons: vec![(6, 50, beacon(&BSSID, SSID, 6, true))],
            ..Default::default()
        };
        let (mut m, _w) = started_mac(default_caps(), Some(&reg), cfg);
        block(m.hw_scan(&[], &[2437])).unwrap();
        let bss = m.bss_table()[0].clone();
        let ies = bss.parsed();
        // The link's channel (HT40+, centre 2447) decides the HT width.
        let (mode, def) = peer::determine_chan(
            m.wiphy(),
            m.own_caps(),
            2437,
            ies.ht_cap.as_ref(),
            ies.ht_oper.as_ref(),
            None,
            None,
        );
        ensure!(mode == peer::ConnMode::Ht, "HT connection");
        ensure!(
            def == ChanDef {
                freq: 2437,
                band: Band::Ghz2,
                width: Width::W40,
                center_freq1: 2447
            },
            "HT40+ at 2447"
        );
        let p = m.assoc_request_params(&bss, &ies, SSID, true);
        let f = frame::build_assoc_req(&p);
        // Without a link mac80211's conn bw_limit is 20 MHz: 40 MHz and
        // SGI40 are cleared (0x19e7 → 0x19a5). The HT40 request is
        // checked on the air in smoke_ath11k_mac_connect_wpa2.
        ensure!(f == exp_assoc_req(0x19A5), "association request bytes");
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_mac_auth_assoc_frames
);

fn smoke_ath11k_mac_frame_parsers() -> TestResult {
    run(|| {
        // Element walk stops at a truncated element.
        let (e, done) = frame::elements(&[0, 2, b'a', b'b', 1, 5, 0x82]);
        ensure!(e.len() == 1 && !done, "truncated tail");
        let (e, done) = frame::elements(&[0, 0, 3, 1, 6]);
        ensure!(e.len() == 2 && done, "complete walk");
        // Short HT cap / op elements are ignored.
        let p = frame::ParsedIes::parse(&[0x2D, 3, 1, 2, 3, 0x3D, 1, 6]);
        ensure!(
            p.ht_cap.is_none() && p.ht_oper.is_none(),
            "short HT elements"
        );
        // DS params must be exactly 1 byte.
        let p = frame::ParsedIes::parse(&[0x03, 2, 6, 0]);
        ensure!(p.ds_channel.is_none(), "DS len 2 ignored");
        // A WMM info element (subtype 0) sets wmm_used but is no param.
        let p = frame::ParsedIes::parse(&[0xDD, 0x07, 0x00, 0x50, 0xF2, 0x02, 0x00, 0x01, 0x00]);
        ensure!(p.wmm_used && p.wmm_param.is_none(), "WMM info");
        // Assoc response AID mask.
        let r = assoc_resp(0);
        let a = frame::parse_assoc_resp(&r).unwrap();
        ensure!(
            a.aid() == 1 && a.capab_info == 0x0431 && a.status == 0,
            "assoc resp fields"
        );
        ensure!(
            frame::parse_assoc_resp(&r[..29]).is_none(),
            "short assoc resp"
        );
        ensure!(frame::parse_auth(&r).is_none(), "assoc resp is not auth");
        // Beacon fixed fields.
        let b = beacon(&BSSID, SSID, 6, true);
        let bf = frame::parse_beacon(&b).unwrap();
        ensure!(
            bf.beacon_int == 100 && bf.capability == 0x0431 && !bf.is_probe_resp,
            "beacon fields"
        );
        ensure!(frame::parse_beacon(&b[..35]).is_none(), "short beacon");
        // Security classification.
        use narf_wireless::scan::BssSecurity;
        let sae = [
            0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00,
            0x00, 0x0F, 0xAC, 0x08, 0xC0, 0x00,
        ];
        let mut ie = vec![0x30, sae.len() as u8];
        ie.extend_from_slice(&sae);
        ensure!(
            matches!(
                bss_security(0x11, &frame::ParsedIes::parse(&ie)),
                BssSecurity::Wpa3
            ),
            "SAE-only → WPA3"
        );
        ensure!(
            matches!(
                bss_security(0x11, &frame::ParsedIes::parse(&[])),
                BssSecurity::Wep
            ),
            "privacy only → WEP"
        );
        ensure!(
            matches!(
                bss_security(0x11, &frame::ParsedIes::parse(&[0x30, 2, 2, 0])),
                BssSecurity::Wep
            ),
            "bad RSN version → WEP"
        );
        // Channel numbering.
        ensure!(frame::channel_to_freq(14, Band::Ghz2) == Some(2484), "ch14");
        ensure!(
            frame::channel_to_freq(2, Band::Ghz6) == Some(5935),
            "6 GHz ch2"
        );
        ensure!(
            frame::freq_to_channel(5935) == 2 && frame::freq_to_channel(5955) == 1,
            "6 GHz numbering"
        );
        ensure!(
            mac::channel_number_freq(149) == Some(5745) && mac::channel_number_freq(0).is_none(),
            "nl80211 channel → freq"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_mac_frame_parsers);

fn smoke_ath11k_mac_key_wrap_vector() -> TestResult {
    run(|| {
        // RFC 3394 §4.1: 128-bit key data with a 128-bit KEK.
        let kek: [u8; 16] = core::array::from_fn(|i| i as u8);
        let key = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let want = [
            0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A,
            0x7B, 0x82, 0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5,
        ];
        ensure!(
            aes_key_wrap(&kek, &key) == want,
            "test-side wrap matches RFC 3394"
        );
        ensure!(
            crate::iwlwifi::rekey::aes_key_unwrap(&kek, &want).as_deref() == Some(&key[..]),
            "the unwrap the mac layer uses"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_mac_key_wrap_vector);

// ── Capabilities / peer assoc ───────────────────────────────────────

fn smoke_ath11k_mac_own_caps() -> TestResult {
    run(|| {
        let c = default_caps();
        let o = peer::own_caps(&c.pdev);
        ensure!(o.num_tx_chains == 2 && o.num_rx_chains == 2, "2x2");
        let h = o.ht_2g;
        ensure!(
            h.ht_supported && h.cap == 0x19E7,
            "HT cap from ht_cap_info 0x185f"
        );
        ensure!(
            h.rx_mask[..3] == [0xFF, 0xFF, 0] && h.tx_params == 1 && h.ampdu_factor == 3,
            "MCS / A-MPDU"
        );
        // ath11k_create_vht_cap: set_vht_txbf_cap keeps SU BFER/BFEE (2
        // chains), sounding dim min(1, 1), STS 3; MCS 0–9 on 2 streams.
        let v = o.vht_5g;
        ensure!(
            v.vht_supported && v.cap == VHT_CAP,
            "VHT cap unchanged for 2x2"
        );
        ensure!(
            v.rx_mcs_map == 0xFFFA && v.tx_mcs_map == 0xFFFA,
            "MCS 0-9 × 2 streams"
        );
        // 1x1: SU BFER / sounding dim / TXSTBC dropped (rate_cap_tx_chainmask 1).
        let mut one = c.pdev;
        one.tx_chain_mask = 1;
        one.rx_chain_mask = 1;
        let o1 = peer::own_caps(&one);
        ensure!(
            o1.vht_5g.cap & peer::vht::SU_BEAMFORMER_CAPABLE == 0,
            "1x1: no SU BFER"
        );
        ensure!(
            o1.vht_5g.cap & peer::vht::SU_BEAMFORMEE_CAPABLE == 0,
            "1x1: no SU BFEE"
        );
        ensure!(o1.vht_5g.cap & peer::vht::TXSTBC == 0, "1x1: no TX STBC");
        ensure!(
            o1.vht_5g.rx_mcs_map == 0xFFFE && o1.ht_2g.rx_mask[1] == 0,
            "1 stream"
        );
        // txbf conf: STS 3 → 0x30, sound dim 1 → 0x100, SU BFER 4, SU BFEE 1, MU BFEE 2.
        ensure!(
            peer::txbf_conf(VHT_CAP, 2) == Some(0x137),
            "vdev txbf param"
        );
        ensure!(peer::txbf_conf(0, 2).is_none(), "no BF → no command");
        // HT disabled in firmware.
        ensure!(
            !peer::create_ht_cap(0x2, 3, 2, 0).ht_supported,
            "!ENABLED → no HT"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_mac_own_caps);

/// The peer assoc arguments for the fixture AP, derived by hand from
/// `ath11k_peer_assoc_prepare` (comments give each value's origin).
fn exp_peer_assoc() -> PeerAssocParams {
    PeerAssocParams {
        vdev_id: 0,
        peer_new_assoc: 1,
        peer_associd: 1,
        peer_mac: BSSID,
        peer_caps: 0x0431,
        peer_listen_intval: 5,
        // sta ht_cap: AP 0x016e & (ours | ~symmetric bits) = 0x016e
        peer_ht_caps: 0x016E,
        // (1 << (13 + 3)) - 1
        peer_max_mpdu: 65535,
        // ath11k_parse_mpdudensity(5) = 4
        peer_mpdu_density: 4,
        // HT | CW40 | SGI | RX_STBC(1) << 6 | DS (rx_mask[1])
        peer_rate_caps: 0x08 | 0x02 | 0x04 | 0x40 | 0x01,
        peer_nss: 2,
        peer_phymode: phy_mode::MODE_11NG_HT40,
        peer_legacy_rates: vec![
            0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6C,
        ],
        peer_ht_rates: (0..16).collect(),
        is_wme_set: true,
        qos_flag: true,
        ht_flag: true,
        bw_40: true,
        stbc_flag: true,
        // SM_PS 3 (disabled) → spatial mux
        spatial_mux_flag: true,
        need_ptk_4_way: true,
        auth_flag: true,
        is_assoc: true,
        ..Default::default()
    }
}

fn smoke_ath11k_mac_peer_assoc_prepare() -> TestResult {
    run(|| {
        let c = default_caps();
        let own = peer::own_caps(&c.pdev);
        let resp = assoc_resp(0);
        let a = frame::parse_assoc_resp(&resp).unwrap();
        let rie = frame::ParsedIes::parse(a.ies);
        let def = ChanDef {
            freq: 2437,
            band: Band::Ghz2,
            width: Width::W40,
            center_freq1: 2447,
        };
        let mut sta = peer::ApSta {
            addr: BSSID,
            ..Default::default()
        };
        sta.ht_cap = peer::sta_ht_cap(own.ht(Band::Ghz2), rie.ht_cap.as_ref());
        ensure!(
            sta.ht_cap.cap == 0x016E && sta.ht_cap.ampdu_density == 5,
            "sta HT cap"
        );
        ensure!(
            sta.ht_cap.rx_mask[..4] == [0xFF, 0xFF, 0, 0],
            "MCS intersection (4 streams max)"
        );
        sta.supp_rates = peer::rates_to_mask(Band::Ghz2, &rie.rates).0;
        ensure!(sta.supp_rates == 0xFFF, "all 12 g rates");
        sta.bandwidth = Some(peer::sta_bandwidth(&sta.ht_cap, &sta.vht_cap, &def));
        ensure!(sta.bandwidth == Some(StaBw::Bw40), "HT40");
        sta.rx_nss = peer::sta_rx_nss(&sta.ht_cap, &sta.vht_cap);
        ensure!(sta.rx_nss == 2, "2 streams");
        sta.wme = true;
        let p = peer::peer_assoc_prepare(&peer::PeerAssocInput {
            vdev_id: 0,
            aid: 1,
            assoc_capability: 0x0431,
            listen_interval: 5,
            def,
            sta: &sta,
            rsn: true,
            wpa: false,
        });
        ensure!(p == exp_peer_assoc(), "peer assoc params");
        // QOS | NEED_PTK_4_WAY | HT | BW_40 | STBC | SPATIAL_MUX; AUTH
        // cleared for the 4-way (is_assoc, hw crypto on).
        ensure!(peer_assoc_flags(&p, false) == 0x0020_B006, "peer_flags");
        // Open network: AUTH kept.
        let mut open = p.clone();
        open.need_ptk_4_way = false;
        ensure!(
            peer_assoc_flags(&open, false) == 0x0020_B003,
            "open peer_flags"
        );
        // 11b-only AP on 2.4 GHz.
        let b = peer::ApSta {
            addr: BSSID,
            supp_rates: 0xF,
            ..Default::default()
        };
        let pb = peer::peer_assoc_prepare(&peer::PeerAssocInput {
            sta: &b,
            def: ChanDef {
                width: Width::W20NoHt,
                center_freq1: 2437,
                ..def
            },
            ..peer::PeerAssocInput {
                vdev_id: 0,
                aid: 2,
                assoc_capability: 1,
                listen_interval: 5,
                def,
                sta: &b,
                rsn: false,
                wpa: false,
            }
        });
        ensure!(
            pb.peer_phymode == phy_mode::MODE_11B
                && pb.peer_legacy_rates == [0x82, 0x84, 0x8B, 0x96],
            "11b"
        );
        ensure!(
            pb.peer_nss == 1 && !pb.ht_flag && pb.peer_ht_rates.is_empty(),
            "legacy nss 1"
        );
        // An HT peer with an empty RX MCS map gets MCS 0–7 (firmware WAR).
        let mut z = sta;
        z.ht_cap.rx_mask = [0; 10];
        let pz = peer::peer_assoc_prepare(&peer::PeerAssocInput {
            sta: &z,
            ..peer::PeerAssocInput {
                vdev_id: 0,
                aid: 1,
                assoc_capability: 1,
                listen_interval: 5,
                def,
                sta: &z,
                rsn: false,
                wpa: false,
            }
        });
        ensure!(
            pz.peer_ht_rates == (0..8).collect::<Vec<u8>>() && pz.peer_nss == 1,
            "MCS 0-7 workaround"
        );
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_mac_peer_assoc_prepare
);

fn smoke_ath11k_mac_vht80_chandef() -> TestResult {
    run(|| {
        let reg = us_reg(false);
        let (m, _) = new_mac(default_caps(), Some(&reg), FwCfg::default());
        let own = m.own_caps();
        let htc = frame::HtCapIe::parse(&ap_ht_cap()[2..]).unwrap();
        let hto = frame::HtOperIe::parse(&ap_ht_oper(36, 0x05)[2..]).unwrap();
        let vc = frame::VhtCapIe {
            vht_cap_info: 0x0F81_59B1,
            rx_mcs_map: 0xFFFA,
            tx_mcs_map: 0xFFFA,
            ..Default::default()
        };
        // VHT op: 80 MHz, centre ch 42.
        let vo = frame::VhtOperIe {
            chan_width: 1,
            center_freq_seg0_idx: 42,
            ..Default::default()
        };
        let (mode, def) = peer::determine_chan(
            m.wiphy(),
            own,
            5180,
            Some(&htc),
            Some(&hto),
            Some(&vc),
            Some(&vo),
        );
        ensure!(mode == peer::ConnMode::Vht, "VHT");
        ensure!(
            def == ChanDef {
                freq: 5180,
                band: Band::Ghz5,
                width: Width::W80,
                center_freq1: 5210
            },
            "VHT80 centre 5210"
        );
        ensure!(
            peer::vdev_phymode(&def) == phy_mode::MODE_11AX_HE80,
            "ath11k_phymodes[5G][80] = HE80"
        );
        // ch 165 can't do 80 MHz (ch 169-177 off) → HT40 ABOVE also off → 20.
        let hto165 = frame::HtOperIe::parse(&ap_ht_oper(165, 0x05)[2..]).unwrap();
        let vo165 = frame::VhtOperIe {
            chan_width: 1,
            center_freq_seg0_idx: 171,
            ..Default::default()
        };
        let (_, d165) = peer::determine_chan(
            m.wiphy(),
            own,
            5825,
            Some(&htc),
            Some(&hto165),
            Some(&vc),
            Some(&vo165),
        );
        ensure!(
            d165.width == Width::W20 && d165.center_freq1 == 5825,
            "downgraded to 20 MHz"
        );
        // Wrong control channel in HT operation → legacy.
        let (mode, d) =
            peer::determine_chan(m.wiphy(), own, 5180, Some(&htc), Some(&hto165), None, None);
        ensure!(
            mode == peer::ConnMode::Legacy && d.width == Width::W20NoHt,
            "mismatched HT op → no HT"
        );
        ensure!(
            peer::vdev_phymode(&d) == phy_mode::MODE_11AX_HE20,
            "20_NOHT → HE20"
        );
        // sta VHT intersection + peer assoc VHT fields.
        let mut sta = peer::ApSta {
            addr: BSSID,
            ..Default::default()
        };
        sta.ht_cap = peer::sta_ht_cap(own.ht(Band::Ghz5), Some(&htc));
        sta.vht_cap = peer::sta_vht_cap(own.vht(Band::Ghz5).unwrap(), &sta.ht_cap, Some(&vc), true);
        ensure!(sta.vht_cap.vht_supported, "VHT peer");
        ensure!(sta.vht_cap.rx_mcs_map == 0xFFFA, "MCS map intersection");
        sta.bandwidth = Some(peer::sta_bandwidth(&sta.ht_cap, &sta.vht_cap, &def));
        ensure!(sta.bandwidth == Some(StaBw::Bw80), "80");
        sta.rx_nss = peer::sta_rx_nss(&sta.ht_cap, &sta.vht_cap);
        let p = peer::peer_assoc_prepare(&peer::PeerAssocInput {
            vdev_id: 0,
            aid: 3,
            assoc_capability: 0x0011,
            listen_interval: 5,
            def,
            sta: &sta,
            rsn: true,
            wpa: false,
        });
        ensure!(
            p.peer_phymode == phy_mode::MODE_11AC_VHT80 && p.bw_80 && p.vht_flag && p.vht_capable,
            "VHT80 phymode/flags"
        );
        ensure!(
            p.rx_mcs_set == 0xFFFA && p.tx_mcs_set == (0xFFFA | (1 << 24)),
            "tx_mcs_set gets DISABLE_VHT_MCS_SUPPORT_0_11"
        );
        ensure!(
            p.peer_nss == 2 && p.peer_legacy_rates.is_empty(),
            "nss 2, no legacy rates listed"
        );
        // A VHT peer whose rx map is all 3s is not VHT.
        let bad = frame::VhtCapIe {
            rx_mcs_map: 0xFFFF,
            ..vc
        };
        ensure!(
            !peer::sta_vht_cap(own.vht(Band::Ghz5).unwrap(), &sta.ht_cap, Some(&bad), true)
                .vht_supported,
            "rx map 0xffff → no VHT"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_mac_vht80_chandef);

// ── Connect ─────────────────────────────────────────────────────────

fn scanned_mac(cfg: FwCfg) -> (TestMac, Shared) {
    let reg = us_reg(false);
    let mut c = cfg;
    c.beacons = vec![
        (6, 50, beacon(&BSSID, SSID, 6, true)),
        (1, 30, beacon(&BSSID2, b"open", 1, false)),
    ];
    let (mut m, w) = started_mac(default_caps(), Some(&reg), c);
    block(m.hw_scan(&[], &[2412, 2437])).unwrap();
    take_sent(&w);
    w.lock().mgmt.clear();
    (m, w)
}

fn wpa2_req() -> AssociateRequest {
    AssociateRequest {
        bssid: BSSID,
        ssid: SSID.to_vec(),
        channel: 6,
        security: SecurityConfig::Wpa2 { psk: PMK },
    }
}

/// Everything up to and including `ath11k_mac_start_vdev_delay`.
fn exp_prep_connection(m: &TestMac) -> Vec<WmiCmd> {
    let def = ChanDef {
        freq: 2437,
        band: Band::Ghz2,
        width: Width::W40,
        center_freq1: 2447,
    };
    let ch = *m.wiphy().get(2437).unwrap();
    let mut arg = VdevStartReqArg {
        vdev_id: 0,
        bcn_intval: 100,
        dtim_period: 0,
        pref_tx_streams: 2,
        pref_rx_streams: 2,
        ..Default::default()
    };
    arg.channel = ChannelArg {
        freq: 2437,
        band_center_freq1: 2447,
        mode: peer::vdev_phymode(&def),
        max_power: ch.max_power as u8,
        max_reg_power: ch.max_reg_power as u8,
        max_antenna_gain: 0,
        ..Default::default()
    };
    vec![
        // ieee80211_recalc_txpower: min(30 dBm, hw_max 30) × 2 = 60 ≠ 30
        pdev(WMI_PDEV_PARAM_TXPOWER_LIMIT2G, 60),
        pdev(WMI_PDEV_PARAM_TXPOWER_LIMIT5G, 60),
        // BSS_CHANGED_BEACON_INT
        vdev(WMI_VDEV_PARAM_BEACON_INTERVAL, 100),
        // BSS_CHANGED_BASIC_RATES: lowest basic = 1 Mbps CCK, hw 3,
        // preamble CCK → (1 << 28) | (1 << 8) | 3
        vdev(WMI_VDEV_PARAM_MGMT_RATE, 0x1000_0103),
        vdev(WMI_VDEV_PARAM_BEACON_RATE, 0x1000_0103),
        // ath11k_mac_station_add → ath11k_peer_create
        peer_create_cmd(0, &BSSID, peer_type::DEFAULT),
        // ath11k_mac_start_vdev_delay → ath11k_mac_vdev_start
        vdev_start_cmd(&arg, false).unwrap(),
        // ath11k_mac_set_txbf_conf
        vdev(WMI_VDEV_PARAM_TXBF, 0x137),
        // WCN6855 clears the mgmt rate at vdev start
        vdev(WMI_VDEV_PARAM_MGMT_RATE, 0x1000_0103),
    ]
}

/// `ieee80211_assoc_success` → `conf_tx` ×4, BSS_CHANGED_* →
/// `ath11k_bss_assoc`.
fn exp_assoc_success(rsn: bool) -> Vec<WmiCmd> {
    let mut wmm = mac::wmm_default(false, false).map(|p| WmmParamsArg {
        cwmin: p.cw_min,
        cwmax: p.cw_max,
        aifs: p.aifs,
        txop: p.txop,
        ..Default::default()
    });
    // arvif->wmm_params after add_interface (WME order is symmetric here).
    let p = frame::WmmParam::parse(&AP_WMM[2..]).unwrap();
    let mut v = exp_conf_tx(&mac::wmm_from_ie(&p), &mut wmm);
    // BEACON_INFO → DTIM 1; ERP: short slot (assoc capab) / short
    // preamble (ERP without Barker) changed → SHORT (2).
    v.push(vdev(WMI_VDEV_PARAM_DTIM_PERIOD, 1));
    v.push(vdev(WMI_VDEV_PARAM_SLOT_TIME, 2));
    v.push(vdev(WMI_VDEV_PARAM_PREAMBLE, 2));
    let mut pa = exp_peer_assoc();
    if !rsn {
        pa.need_ptk_4_way = false;
    }
    v.push(peer_assoc_cmd(&pa, false).unwrap());
    // ath11k_setup_peer_smps: SM_PS disabled → WMI_PEER_SMPS_PS_NONE
    v.push(peer_set_param_cmd(&BSSID, 0, peer_param::MIMO_PS_STATE, 0));
    v.push(vdev_up_cmd(0, 1, &BSSID, None, 0, 0, None));
    if !rsn {
        // Open: authorized before BSS_CHANGED_ASSOC.
        v.push(peer_set_param_cmd(&BSSID, 0, peer_param::AUTHORIZE, 1));
    }
    v.push(obss_spr_cmd(0, 0, 0, 0));
    v.push(vdev(WMI_VDEV_PARAM_DTIM_POLICY, 3));
    // ath11k_mac_11d_scan_stop_all
    v.push(scan_11d_stop_cmd(0));
    v
}

fn ps_on() -> Vec<WmiCmd> {
    vec![
        ps(sta_ps_param::INACTIVITY_TIME, 100),
        sta_powersave_mode_cmd(0, sta_ps_mode::ENABLED),
    ]
}

fn smoke_ath11k_mac_connect_wpa2() -> TestResult {
    run(|| {
        let (mut m, w) = scanned_mac(FwCfg {
            eapol: true,
            ..Default::default()
        });
        let r = block(m.connect(&wpa2_req()));
        ensure!(r.is_ok(), "WPA2 connect");
        let sent = take_sent(&w);
        let mut want = exp_prep_connection(&m);
        want.extend(exp_assoc_success(true));
        let ptk = w.lock().ap.ptk.clone().unwrap();
        want.push(vdev_install_key_cmd(&VdevInstallKeyArg {
            vdev_id: 0,
            macaddr: BSSID,
            key_idx: 0,
            key_flags: WMI_KEY_PAIRWISE,
            key_cipher: cipher::AES_CCM,
            key_data: ptk.tk.clone(),
            ..Default::default()
        }));
        want.push(vdev_install_key_cmd(&VdevInstallKeyArg {
            vdev_id: 0,
            macaddr: BSSID,
            key_idx: GTK_IDX as u32,
            key_flags: WMI_KEY_GROUP,
            key_cipher: cipher::AES_CCM,
            key_data: GTK.to_vec(),
            ..Default::default()
        }));
        want.push(peer_set_param_cmd(&BSSID, 0, peer_param::AUTHORIZE, 1));
        want.extend(ps_on());
        ensure!(same_cmds(&sent, &want), "WPA2 join command list");
        let g = w.lock();
        ensure!(g.ap.m2_mic_ok, "M2 MIC verifies with the AP's PTK");
        ensure!(g.ap.m2_rsn_ok, "M2 carries our RSN element");
        ensure!(g.ap.m4_ok, "M4 MIC + replay counter");
        ensure!(g.authorized == Some(true), "port authorized");
        ensure!(
            g.pn == [
                (cipher::AES_CCM, true, true),
                (cipher::AES_CCM, false, true)
            ],
            "PN replay config for PTK then GTK"
        );
        ensure!(g.mgmt.len() == 2, "auth + assoc request");
        ensure!(
            g.mgmt[0] == frame::build_auth_open(&OWN, &BSSID),
            "auth frame sent"
        );
        ensure!(
            g.mgmt[1] == exp_assoc_req(0x19E7),
            "HT40 association request on the air"
        );
        ensure!(
            g.done_descs == [1, 2],
            "both mgmt buffers released on completion"
        );
        ensure!(
            g.dp_calls
                .iter()
                .filter(|c| **c == "peer_map" || **c == "peer_setup")
                .count()
                == 2,
            "peer map wait + dp peer setup"
        );
        // M2: version 2 | pairwise | MIC, replay 1, SNonce, RSN element.
        let (_, pdu) = frame::parse_eapol_eth(&g.eth_tx[0]).unwrap();
        let m2 = KeyFrame::decode(&pdu[4..], 16).unwrap();
        ensure!(
            m2.key_information == 0x010A
                && m2.replay_counter == 1
                && m2.key_nonce == [SNONCE_FILL; 32],
            "M2 fields"
        );
        ensure!(pdu[0] == 3 && pdu[1] == 3, "EAPOL v3 key frame");
        // 4 + 95 (16-byte MIC for AKM 2) + 22-byte RSN element.
        ensure!(
            pdu.len() == 121 && pdu[2..4] == [0, 117],
            "M2 length: 16-byte Key MIC"
        );
        drop(g);
        ensure!(m.connected_bssid() == Some(BSSID), "connected");
        ensure!(
            narf_memory::diag::snapshot().wifi_stage == narf_memory::diag::WifiStage::Connected,
            "stage Connected"
        );
        let v = m.vif().unwrap();
        ensure!(
            v.is_up && v.is_started && v.aid == 1 && v.ps,
            "vif up / started / aid / ps"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_mac_connect_wpa2);

fn smoke_ath11k_mac_connect_open_and_disconnect() -> TestResult {
    run(|| {
        let (mut m, w) = scanned_mac(FwCfg::default());
        // Open to a WPA2 BSS is refused before any command.
        let mut bad = wpa2_req();
        bad.security = SecurityConfig::Open;
        let (r, err, _) = latched(|| block(m.connect(&bad)));
        ensure!(
            r.is_err() && err == step::CONNECT_UNSUPPORTED && take_sent(&w).is_empty(),
            "open to RSN refused"
        );
        // WPA3 not implemented.
        let mut sae = wpa2_req();
        sae.security = SecurityConfig::Wpa3 {
            password: b"x".to_vec(),
        };
        ensure!(
            block(m.associate(&sae)) == Err(narf_wireless::WirelessError::NotSupported),
            "SAE"
        );
        // Unknown BSS.
        let mut unk = wpa2_req();
        unk.bssid = [0x02, 0, 0, 0, 0, 9];
        let (r, err, _) = latched(|| block(m.connect(&unk)));
        ensure!(
            r.map_err(|e| e.errno) == Err(2) && err == step::CONNECT_NO_BSS,
            "not scanned → -ENOENT"
        );

        // The open BSS on channel 1 (HT40+ at 2422).
        let req = AssociateRequest {
            bssid: BSSID2,
            ssid: b"open".to_vec(),
            channel: 1,
            security: SecurityConfig::Open,
        };
        // Answer as BSSID2.
        let r = block(async {
            // The fake AP answers with BSSID; retarget it.
            m.connect(&req).await
        });
        // The fake AP only knows BSSID: the auth goes unanswered.
        ensure!(
            r.map_err(|e| e.step) == Err(step::AUTH_TIMEOUT),
            "auth to a silent AP times out"
        );
        let g = w.lock();
        ensure!(
            g.mgmt.len() == 3,
            "three auth attempts (IEEE80211_AUTH_MAX_TRIES)"
        );
        drop(g);
        let sent = take_sent(&w);
        // Teardown before association: no VDEV_DOWN; vdev stop + peer delete.
        ensure!(
            !sent.iter().any(|c| c.cmd_id == WMI_VDEV_DOWN_CMDID),
            "no vdev down before assoc"
        );
        let tail: Vec<u32> = sent.iter().rev().take(2).map(|c| c.cmd_id).collect();
        ensure!(
            tail == [WMI_PEER_DELETE_CMDID, WMI_VDEV_STOP_CMDID],
            "vdev stop then peer delete"
        );
        ensure!(
            m.link().is_none() && !m.vif().unwrap().is_started,
            "state cleared"
        );
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_mac_connect_open_and_disconnect
);

fn open_ap_mac() -> (TestMac, Shared) {
    // An open AP at BSSID (the fake AP's address).
    let reg = us_reg(false);
    let c = FwCfg {
        beacons: vec![(6, 50, beacon(&BSSID, SSID, 6, false))],
        ..Default::default()
    };
    let (mut m, w) = started_mac(default_caps(), Some(&reg), c);
    block(m.hw_scan(&[], &[2437])).unwrap();
    take_sent(&w);
    (m, w)
}

fn open_req() -> AssociateRequest {
    AssociateRequest {
        bssid: BSSID,
        ssid: SSID.to_vec(),
        channel: 6,
        security: SecurityConfig::Open,
    }
}

/// `ieee80211_set_disassoc` + `unassign_vif_chanctx` after a full open
/// association.
fn exp_disconnect(ptk: bool) -> Vec<WmiCmd> {
    let mut v = Vec::new();
    if ptk {
        v.push(vdev_install_key_cmd(&VdevInstallKeyArg {
            vdev_id: 0,
            macaddr: BSSID,
            key_idx: 0,
            key_flags: WMI_KEY_PAIRWISE,
            key_cipher: cipher::NONE,
            ..Default::default()
        }));
    }
    v.push(vdev_stop_cmd(0));
    v.push(peer_delete_cmd(&BSSID, 0));
    v.push(vdev(WMI_VDEV_PARAM_SLOT_TIME, 1));
    v.push(vdev(WMI_VDEV_PARAM_PREAMBLE, 1));
    v.push(vdev_down_cmd(0));
    // arvif->wmm_params still hold the AP's values, overwritten AC by AC.
    let p = frame::WmmParam::parse(&AP_WMM[2..]).unwrap();
    let mut wmm = [WmmParamsArg::default(); 4];
    let _ = exp_conf_tx(&mac::wmm_default(false, false), &mut wmm);
    let _ = exp_conf_tx(&mac::wmm_from_ie(&p), &mut wmm);
    v.extend(exp_conf_tx(&mac::wmm_default(false, false), &mut wmm));
    // unassign → ath11k_mac_11d_scan_start
    v.push(scan_11d_start_cmd(0, 600_000, 0));
    v
}

fn smoke_ath11k_mac_open_connect_disconnect() -> TestResult {
    run(|| {
        let (mut m, w) = open_ap_mac();
        ensure!(block(m.connect(&open_req())).is_ok(), "open connect");
        let sent = take_sent(&w);
        let mut want = exp_prep_connection(&m);
        want.extend(exp_assoc_success(false));
        want.extend(ps_on());
        ensure!(same_cmds(&sent, &want), "open join command list");
        ensure!(w.lock().eth_tx.is_empty(), "no EAPOL");
        // Disconnect: deauth (reason 3), then the teardown.
        w.lock().mgmt.clear();
        ensure!(block(m.disassociate()).is_ok(), "disassociate");
        let sent = take_sent(&w);
        ensure!(
            same_cmds(&sent, &exp_disconnect(false)),
            "disconnect command list"
        );
        let g = w.lock();
        ensure!(
            g.mgmt.len() == 1 && g.mgmt[0] == frame::build_deauth(&OWN, &BSSID, 3),
            "deauth reason 3"
        );
        ensure!(g.authorized == Some(false), "port closed");
        ensure!(
            g.dp_calls.contains(&"peer_cleanup") && g.dp_calls.contains(&"peer_unmap"),
            "dp peer cleanup + unmap wait"
        );
        drop(g);
        ensure!(
            m.link().is_none() && m.connected_bssid().is_none(),
            "disconnected"
        );
        ensure!(
            block(m.disassociate()).is_ok() && take_sent(&w).is_empty(),
            "second disassociate is a no-op"
        );
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_mac_open_connect_disconnect
);

fn smoke_ath11k_mac_connect_negatives() -> TestResult {
    run(|| {
        // VDEV_START_RESP with a failure status.
        let (mut m, w) = open_ap_mac();
        set_cfg(&w, |c| c.vdev_start_status = Some(2));
        let (r, err, detail) = latched(|| block(m.connect(&open_req())));
        ensure!(
            r.map_err(|e| e.errno) == Err(22) && err == step::VDEV_START_STATUS && detail == 2,
            "vdev start status → -EINVAL"
        );
        let sent = take_sent(&w);
        ensure!(
            sent.last().unwrap().cmd_id == WMI_PEER_DELETE_CMDID,
            "peer removed after failed start"
        );
        ensure!(
            !sent.iter().any(|c| c.cmd_id == WMI_VDEV_STOP_CMDID),
            "never started → no stop"
        );
        ensure!(w.lock().mgmt.is_empty(), "no auth on a failed start");

        // No VDEV_START_RESP.
        set_cfg(&w, |c| c.vdev_start_status = None);
        let (r, err, _) = latched(|| block(m.connect(&open_req())));
        ensure!(
            r.map_err(|e| e.errno) == Err(110) && err == step::VDEV_START_TIMEOUT,
            "vdev start timeout"
        );

        // No PEER_MAP.
        set_cfg(&w, |c| {
            c.vdev_start_status = Some(0);
            c.peer_map = false;
        });
        take_sent(&w);
        let (r, err, _) = latched(|| block(m.connect(&open_req())));
        ensure!(
            r.is_err() && err == step::PEER_MAP_TIMEOUT,
            "peer map timeout"
        );

        // Authentication denied (status 1).
        set_cfg(&w, |c| {
            c.peer_map = true;
            c.auth_status = Some(1);
        });
        let (r, err, detail) = latched(|| block(m.connect(&open_req())));
        ensure!(
            r.map_err(|e| e.errno) == Err(111) && err == step::AUTH_REJECTED && detail == 1,
            "auth denied"
        );

        // Association rejected (status 17: AP unable to handle more STAs).
        set_cfg(&w, |c| {
            c.auth_status = Some(0);
            c.assoc_status = Some(17);
        });
        take_sent(&w);
        let (r, err, detail) = latched(|| block(m.associate(&open_req())));
        ensure!(
            r == Err(narf_wireless::WirelessError::Denied),
            "assoc reject → Denied"
        );
        ensure!(
            err == step::ASSOC_REJECTED && detail == 17,
            "assoc reject latched with the status"
        );
        let sent = take_sent(&w);
        ensure!(
            !sent
                .iter()
                .any(|c| c.cmd_id == WMI_PEER_ASSOC_CMDID || c.cmd_id == WMI_VDEV_DOWN_CMDID),
            "no peer assoc / vdev down"
        );

        // No PEER_ASSOC_CONF.
        set_cfg(&w, |c| {
            c.assoc_status = Some(0);
            c.peer_assoc_conf = false;
        });
        take_sent(&w);
        let (r, err, _) = latched(|| block(m.connect(&open_req())));
        ensure!(
            r.is_err() && err == step::PEER_ASSOC_TIMEOUT,
            "peer assoc conf timeout"
        );
        let sent = take_sent(&w);
        ensure!(
            sent.iter().any(|c| c.cmd_id == WMI_VDEV_DOWN_CMDID),
            "associated → vdev down in teardown"
        );
        ensure!(m.link().is_none(), "torn down");

        // A silent AP with unacked frames: 3 auth tries, -ETIMEDOUT, and
        // the BSS leaves the table (cfg80211_unlink_bss).
        set_cfg(&w, |c| {
            c.peer_assoc_conf = true;
            c.auth_status = None;
            c.mgmt_ack = false;
        });
        w.lock().mgmt.clear();
        let (r, err, detail) = latched(|| block(m.connect(&open_req())));
        ensure!(
            r.map_err(|e| e.errno) == Err(110) && err == step::AUTH_TIMEOUT && detail == 3,
            "auth timeout"
        );
        ensure!(w.lock().mgmt.len() == 3, "IEEE80211_AUTH_MAX_TRIES");
        ensure!(
            m.bss_table().iter().all(|b| b.bssid != BSSID),
            "BSS unlinked"
        );
        let (r, err, _) = latched(|| block(m.connect(&open_req())));
        ensure!(
            r.is_err() && err == step::CONNECT_NO_BSS,
            "needs a new scan"
        );

        // Rescan; then the AP answers auth but not assoc: 3 acked assoc
        // tries.
        set_cfg(&w, |c| {
            c.mgmt_ack = true;
            c.auth_status = Some(0);
            c.assoc_status = None;
        });
        block(m.hw_scan(&[], &[2437])).unwrap();
        w.lock().mgmt.clear();
        let (r, err, _) = latched(|| block(m.connect(&open_req())));
        ensure!(r.is_err() && err == step::ASSOC_TIMEOUT, "assoc timeout");
        let g = w.lock();
        ensure!(
            g.mgmt.len() == 4 && g.mgmt[1..].iter().all(|f| f[0] == 0x00),
            "1 auth + 3 assoc requests"
        );
        drop(g);
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_mac_connect_negatives
);

fn smoke_ath11k_mac_four_way_negatives() -> TestResult {
    run(|| {
        // Bad M3 MIC: dropped, then the 10 s timeout as a MIC failure;
        // deauth is sent and no key is installed.
        let (mut m, w) = scanned_mac(FwCfg {
            eapol: true,
            bad_m3_mic: true,
            ..Default::default()
        });
        let (r, err, _) = latched(|| block(m.connect(&wpa2_req())));
        ensure!(
            r.map_err(|e| e.errno) == Err(110) && err == step::EAPOL_MIC,
            "M3 MIC failure"
        );
        let sent = take_sent(&w);
        ensure!(
            !sent.iter().any(|c| c.cmd_id == WMI_VDEV_INSTALL_KEY_CMDID),
            "no key installed"
        );
        ensure!(
            w.lock().mgmt.last().unwrap() == &frame::build_deauth(&OWN, &BSSID, 3),
            "deauth after a failed handshake"
        );
        ensure!(w.lock().authorized != Some(true), "never authorized");

        // No M1 at all: plain timeout.
        let (mut m, w) = scanned_mac(FwCfg {
            eapol: true,
            send_m1: false,
            ..Default::default()
        });
        let t0 = w.lock().now;
        let (r, err, _) = latched(|| block(m.connect(&wpa2_req())));
        ensure!(r.is_err() && err == step::EAPOL_TIMEOUT, "4-way timeout");
        ensure!(w.lock().now - t0 >= 10_000, "10 s auth timeout");

        // M3 RSN element ≠ beacon's: deauth with WLAN_REASON_IE_DIFFERENT.
        let mut other = AP_RSN_IE.to_vec();
        other[20] = 0x00;
        let (mut m, w) = scanned_mac(FwCfg {
            eapol: true,
            m3_rsn: Some(other),
            ..Default::default()
        });
        let (r, err, detail) = latched(|| block(m.connect(&wpa2_req())));
        ensure!(
            r.is_err() && err == step::EAPOL_PROTO && detail == 4,
            "RSN IE mismatch"
        );
        ensure!(
            w.lock().mgmt.last().unwrap() == &frame::build_deauth(&OWN, &BSSID, 17),
            "reason 17"
        );

        // INSTALL_KEY_COMPLETE with a failure status.
        let (mut m, w) = scanned_mac(FwCfg {
            eapol: true,
            install_key_status: Some(1),
            ..Default::default()
        });
        let (r, err, detail) = latched(|| block(m.connect(&wpa2_req())));
        ensure!(
            r.is_err() && err == step::KEY_INSTALL_STATUS && detail == 1,
            "install key status"
        );
        let sent = take_sent(&w);
        ensure!(
            sent.iter()
                .filter(|c| c.cmd_id == WMI_VDEV_INSTALL_KEY_CMDID)
                .count()
                == 1,
            "PTK only; no DISABLE_KEY for a key that never installed"
        );
        ensure!(
            sent.iter().any(|c| c.cmd_id == WMI_VDEV_DOWN_CMDID),
            "vdev down"
        );
        // No completion at all.
        let (mut m, _w) = scanned_mac(FwCfg {
            eapol: true,
            install_key_status: None,
            ..Default::default()
        });
        let (r, err, _) = latched(|| block(m.connect(&wpa2_req())));
        ensure!(
            r.is_err() && err == step::KEY_INSTALL_TIMEOUT,
            "install key timeout"
        );
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_mac_four_way_negatives
);

fn smoke_ath11k_mac_link_loss() -> TestResult {
    run(|| {
        // Kickout of the AP peer → disconnected, deauth reason 4.
        let (mut m, w) = open_ap_mac();
        block(m.connect(&open_req())).unwrap();
        take_sent(&w);
        w.lock().mgmt.clear();
        let mw = mac_words(&BSSID);
        // A kickout for another peer is ignored.
        let other = mac_words(&[0x02, 1, 1, 1, 1, 1]);
        w.lock().events.push_back(event(
            WMI_PEER_STA_KICKOUT_EVENTID,
            &[tlv(
                WMI_TAG_PEER_STA_KICKOUT_EVENT,
                &le(&[other[0], other[1]]),
            )],
        ));
        ensure!(
            block(m.poll()).is_none() && m.connected_bssid().is_some(),
            "foreign kickout ignored"
        );
        w.lock().events.push_back(event(
            WMI_PEER_STA_KICKOUT_EVENTID,
            &[tlv(WMI_TAG_PEER_STA_KICKOUT_EVENT, &le(&[mw[0], mw[1]]))],
        ));
        let (l, err, _) = latched(|| block(m.poll()));
        ensure!(
            l == Some(LinkLoss::Kickout) && err == step::LINK_KICKOUT,
            "kickout → link loss"
        );
        ensure!(m.link().is_none(), "torn down");
        ensure!(
            w.lock().mgmt.last().unwrap() == &frame::build_deauth(&OWN, &BSSID, 4),
            "deauth reason 4"
        );
        let sent = take_sent(&w);
        ensure!(
            same_cmds(&sent, &exp_disconnect(false)),
            "same teardown as disassociate"
        );

        // Beacon miss: ROAM(BEACON_MISS) arms 3 s; a beacon cancels it.
        let (mut m, w) = open_ap_mac();
        block(m.connect(&open_req())).unwrap();
        let roam = event(
            WMI_ROAM_EVENTID,
            &[tlv(WMI_TAG_ROAM_EVENT, &le(&[0, 2, 0]))],
        );
        w.lock().events.push_back(roam.clone());
        ensure!(block(m.poll()).is_none(), "armed");
        w.lock().now += 1000;
        w.lock().events.push_back(mgmt_rx_event(
            6,
            50,
            2437,
            0,
            &beacon(&BSSID, SSID, 6, false),
        ));
        w.lock().now += 5000;
        ensure!(
            block(m.poll()).is_none() && m.connected_bssid().is_some(),
            "beacon cancels connection loss"
        );
        // Better-AP reason is ignored.
        w.lock().events.push_back(event(
            WMI_ROAM_EVENTID,
            &[tlv(WMI_TAG_ROAM_EVENT, &le(&[0, 1, 0]))],
        ));
        w.lock().now += 5000;
        ensure!(block(m.poll()).is_none(), "BETTER_AP ignored");
        // Beacon miss with silence for 3 s → connection loss.
        w.lock().events.push_back(roam);
        ensure!(block(m.poll()).is_none(), "armed again");
        w.lock().now += 2999;
        ensure!(block(m.poll()).is_none(), "not yet");
        w.lock().now += 1;
        let (l, err, _) = latched(|| block(m.poll()));
        ensure!(
            l == Some(LinkLoss::BeaconLoss) && err == step::LINK_BEACON_LOSS,
            "beacon loss after 3 s"
        );
        ensure!(m.link().is_none(), "disconnected");

        // Deauthentication from the AP: no deauth sent back.
        let (mut m, w) = open_ap_mac();
        block(m.connect(&open_req())).unwrap();
        w.lock().mgmt.clear();
        let mut d = frame::build_deauth(&BSSID, &BSSID, 7);
        d[4..10].copy_from_slice(&OWN);
        w.lock().events.push_back(mgmt_rx_event(6, 50, 2437, 0, &d));
        let (l, err, detail) = latched(|| block(m.poll()));
        ensure!(
            l == Some(LinkLoss::Deauth {
                deauth: true,
                reason: 7
            }),
            "deauth reason 7"
        );
        ensure!(
            err == step::LINK_DEAUTH_RX && detail == 0x1_0007,
            "latched deauth + reason"
        );
        ensure!(w.lock().mgmt.is_empty(), "no deauth reply");
        ensure!(m.link().is_none(), "disconnected");
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_mac_link_loss);

fn smoke_ath11k_mac_11d_new_country() -> TestResult {
    run(|| {
        // WMI_11D_NEW_COUNTRY_EVENTID → state IDLE + ath11k_update_11d →
        // SET_CURRENT_COUNTRY(alpha2 "DE\0").
        let (mut m, w) = started_mac(default_caps(), Some(&us_reg(false)), FwCfg::default());
        let cc = u32::from_le_bytes([b'D', b'E', 0, 0]);
        w.lock().events.push_back(event(
            WMI_11D_NEW_COUNTRY_EVENTID,
            &[tlv(WMI_TAG_11D_NEW_COUNTRY_EVENT, &le(&[cc]))],
        ));
        let _ = block(m.poll());
        let sent = take_sent(&w);
        ensure!(
            sent == [set_current_country_cmd(PDEV, *b"DE\0")],
            "set current country"
        );
        ensure!(m.state_11d() == State11d::Idle, "11d idle");
        // Missing TLV → -EPROTO.
        ensure!(
            decode_11d_new_cc(&[]).map_err(|e| e.errno()) == Err(71),
            "11d event needs its TLV"
        );
        // A new REG_CHAN_LIST_CC for DE then re-sends the channel list.
        let mut ev = le(&[
            0,
            0,
            u32::from_le_bytes([b'D', b'E', 0, 0]),
            1,
            276,
            0x37,
            2,
            0,
            20,
            40,
            20,
            160,
            1,
            1,
        ]);
        let rule =
            |s: u32, e: u32, bw: u32, p: u32, f: u32| le(&[12, s | (e << 16), bw | (p << 16), f]);
        let mut rules = rule(2400, 2483, 40, 20, 0);
        rules.extend(rule(5150, 5250, 80, 23, 0));
        let mut body = tlv(WMI_TAG_REG_CHAN_LIST_CC_EVENT, &ev);
        body.extend(tlv(WMI_TAG_ARRAY_STRUCT, &rules));
        ev = le(&[WMI_REG_CHAN_LIST_CC_EVENTID]);
        ev.extend(body);
        w.lock().events.push_back(ev);
        let _ = block(m.poll());
        let sent = take_sent(&w);
        ensure!(
            m.wiphy().get(5260).unwrap().flags & chan_flag::DISABLED != 0,
            "DE ∩ US: ch52 gone"
        );
        ensure!(sent == chan_list_cmds(&m), "channel list re-sent");
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_mac_11d_new_country);

/// Unused helper kept for symmetry with the wiphy type in signatures.
fn _wiphy_type(_: &Wiphy) {}
