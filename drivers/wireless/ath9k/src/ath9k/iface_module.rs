//! The module build's netdev glue (`ath9k.ko`): the station netdev
//! [`super::interface`] publishes, behind the netif bridge and the `WIFI`
//! family host instead of `narf_net`/nl80211.
//!
//! Built in, `interface.rs` registers its [`Netdev`](super::interface) with
//! the kernel's interface registry, nl80211 and the stack's RX path. A
//! module reaches the network stack only through the netif bridge and the
//! `WIFI` family host (`wireless/src/module_host.rs`, version 2), so this
//! is the same netdev — the same generations, rings, station and in-driver
//! WPA2 supplicant, call for call — with its kernel edges swapped:
//!
//! - **netdev** — `narf_netif_register_with_context` (the bridge names it
//!   `wlan%d` because the device has a wireless session); the stack's TX
//!   frames arrive in [`tx_callback`] and go to the same
//!   `interface::send` the built-in stack calls; RX that `interface.rs`
//!   hands the stack (`on_rx_frame_from`) goes out through
//!   `narf_netif_rx` ([`deliver`]);
//! - **wiphy** — `REGISTER_WIPHY` binds the shell to that netdev and
//!   advertises the attached generation's permitted 2.4/5 GHz channels, its
//!   HT grant, CCMP and PSK offload (the 4-way handshake runs in the
//!   driver);
//! - **control** — the host's `SCAN_REQUEST` / `CONNECT` / `DISCONNECT`
//!   events run the netdev's `scan` / `associate` / `disassociate` (the
//!   built-in `WirelessNetIface` methods), whose outcomes go back as
//!   `SCAN_RESULT` / `SCAN_DONE` / `CONNECT_RESULT` / `DISCONNECTED`;
//! - **link** — carrier follows those reports; a carrier loss the netdev
//!   detects (the built-in `notify_disconnect`) is reported as
//!   `DISCONNECTED` ([`link_lost`]).
//!
//! Not carried (built-in only): nl80211 power-save control, WoW and the
//! userspace SME (the `WIFI` v2 host carries none of them), and system
//! suspend/resume (no module device-PM export). Device removal is module
//! unload (`narf_module_exit`).

use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use narf_module_rt::sync::SpinLock;
use narf_wireless::scan::BssSecurity;
use narf_wireless::{
    AssociateRequest, BssInfo, ScanRequest, SecurityConfig, WirelessError, WirelessIfaceInfo,
};

use super::platform::{self, Console, WirelessNetIface};

/// KABI exports the netdev glue calls.
mod ffi {
    unsafe extern "C" {
        pub fn narf_netif_register_with_context(
            dev: u64,
            mac: *const u8,
            tx_callback: usize,
            out_ifindex: *mut u32,
        ) -> i32;
        pub fn narf_netif_rx(dev: u64, ifindex: u32, frame: *mut u8, len: usize) -> i32;
        pub fn narf_wireless_open_with_event(
            dev: u64,
            family: u32,
            version: u32,
            event_callback: usize,
            out_session: *mut u64,
        ) -> i32;
        pub fn narf_wireless_submit(
            dev: u64,
            session: u64,
            opcode: u32,
            request: *const u8,
            len: usize,
            out_op: *mut u64,
        ) -> i32;
        pub fn narf_wireless_poll(
            dev: u64,
            session: u64,
            op: u64,
            reply: *mut u8,
            len: usize,
            out_len: *mut usize,
        ) -> i32;
    }
}

/// `WIFI` family host, version 2 (`wireless/src/module_host.rs`).
mod wifi {
    pub const FAMILY: u32 = 0x7769_6669;
    pub const VERSION: u32 = 2;
    pub const OP_REGISTER_WIPHY: u32 = 0x01;
    pub const OP_SCAN_RESULT: u32 = 0x02;
    pub const OP_SCAN_DONE: u32 = 0x03;
    pub const OP_CONNECT_RESULT: u32 = 0x04;
    pub const OP_DISCONNECTED: u32 = 0x05;
    pub const EVENT_SCAN_REQUEST: u32 = 0x01;
    pub const EVENT_CONNECT: u32 = 0x02;
    pub const EVENT_DISCONNECT: u32 = 0x03;
    pub const EVENT_SCAN_ABORT: u32 = 0x04;
    pub const FLAG_PSK_OFFLOAD: u8 = 0x01;
    pub const FLAG_REPORTS_DISCONNECT: u8 = 0x04;
    pub const SECURITY_OPEN: u8 = 0;
    pub const SECURITY_PSK: u8 = 1;
    /// IEEE 802.11 status: unspecified failure.
    pub const STATUS_UNSPECIFIED_FAILURE: u16 = 1;
    /// IEEE 802.11 reason: deauthenticated because the station is leaving.
    pub const REASON_DEAUTH_LEAVING: u16 = 3;
}

const ENODEV: i32 = -19;
const ENOBUFS: i32 = -105;
const EINVAL: i32 = -22;

/// The session and netdev of the bound radio (0 until [`open`]).
static SESSION: AtomicU64 = AtomicU64::new(0);
static IFINDEX: AtomicU32 = AtomicU32::new(0);
/// Carrier as last reported to the host (`CONNECT_RESULT` success).
static CONNECTED: AtomicBool = AtomicBool::new(false);
/// A host `DISCONNECT` is being served: its own report is the one sent.
static LEAVING: AtomicBool = AtomicBool::new(false);
/// The last scan's networks, for a `CONNECT` without a BSSID.
static LAST_SCAN: SpinLock<Vec<BssInfo>> = SpinLock::new(Vec::new());

fn log(args: core::fmt::Arguments<'_>) {
    let _ = writeln!(Console, "  ath9k.ko: {}", args);
}

/// Submit a report to the family host and collect its status (every v2
/// report completes at submit).
fn report(opcode: u32, request: &[u8]) -> i32 {
    let session = SESSION.load(Ordering::Acquire);
    if session == 0 {
        return ENODEV;
    }
    let mut op = 0u64;
    // SAFETY: `request` names `len` readable bytes; `op` is a live local.
    let rc = unsafe {
        ffi::narf_wireless_submit(
            platform::device(),
            session,
            opcode,
            request.as_ptr(),
            request.len(),
            &mut op,
        )
    };
    if rc != 0 {
        return rc;
    }
    let mut reply = [0u8; 16];
    let mut len = 0usize;
    // SAFETY: `reply` names 16 writable bytes; `len` is a live local.
    unsafe {
        ffi::narf_wireless_poll(
            platform::device(),
            session,
            op,
            reply.as_mut_ptr(),
            reply.len(),
            &mut len,
        )
    }
}

/// Open the `WIFI` session, then the netif netdev (in that order, so the
/// bridge names it `wlan%d`). Called once, for the first generation.
pub(crate) fn open(mac: [u8; 6]) -> Result<(), i32> {
    let dev = platform::device();
    let mut session = 0u64;
    // SAFETY: `event_callback` is a valid extern "C" fn in this image;
    // `session` is a live local.
    let rc = unsafe {
        ffi::narf_wireless_open_with_event(
            dev,
            wifi::FAMILY,
            wifi::VERSION,
            event_callback as usize,
            &mut session,
        )
    };
    if rc != 0 {
        log(format_args!(
            "wireless session refused ({rc}); no wlan interface"
        ));
        return Err(rc);
    }
    SESSION.store(session, Ordering::Release);
    let mut ifindex = 0u32;
    // SAFETY: `mac` names six readable bytes; `tx_callback` is a valid
    // extern "C" fn in this image; `ifindex` is a live local.
    let rc = unsafe {
        ffi::narf_netif_register_with_context(dev, mac.as_ptr(), tx_callback as usize, &mut ifindex)
    };
    if rc != 0 {
        log(format_args!("netdev registration refused ({rc})"));
        return Err(rc);
    }
    IFINDEX.store(ifindex, Ordering::Release);
    Ok(())
}

/// `REGISTER_WIPHY` for the netdev [`open`] registered.
pub(crate) fn register_wiphy(info: WirelessIfaceInfo) {
    let ifindex = IFINDEX.load(Ordering::Acquire);
    match encode_register_wiphy(ifindex, &info) {
        Some(wiphy) => {
            let rc = report(wifi::OP_REGISTER_WIPHY, &wiphy);
            if rc != 0 {
                log(format_args!("wiphy registration refused ({rc})"));
            } else {
                log(format_args!(
                    "wlan (ifindex {ifindex}) published, MAC {:02x?}",
                    info.base_mac
                ));
            }
        }
        None => log(format_args!("no permitted channel: wiphy not registered")),
    }
}

/// Deliver one received Ethernet frame to the stack (`narf_netif_rx`).
pub(crate) fn deliver(frame: &mut [u8]) {
    let ifindex = IFINDEX.load(Ordering::Acquire);
    if ifindex == 0 || frame.is_empty() {
        return;
    }
    // SAFETY: `frame` names `len` bytes the call may rewrite in place.
    let _ =
        unsafe { ffi::narf_netif_rx(platform::device(), ifindex, frame.as_mut_ptr(), frame.len()) };
}

/// The netdev lost carrier (the built-in `nl80211::notify_disconnect`): a
/// link loss, disassociation or a retired generation. Reported once, and
/// not while a host `DISCONNECT` reports its own completion.
pub(crate) fn link_lost(reason: u16) {
    if LEAVING.load(Ordering::Acquire) || !CONNECTED.swap(false, Ordering::AcqRel) {
        return;
    }
    let _ = report(wifi::OP_DISCONNECTED, &encode_disconnected(reason, false));
}

/// Netif TX: the stack hands one Ethernet frame (borrowed for this call);
/// it is copied into the netdev's TX ring exactly as the built-in stack's
/// send does.
extern "C" fn tx_callback(_dev: u64, frame: *const u8, len: usize) -> i32 {
    if frame.is_null() || len < 14 {
        return EINVAL;
    }
    // SAFETY: the bridge lends `len` readable bytes for the call.
    let bytes = unsafe { core::slice::from_raw_parts(frame, len) };
    match super::interface::send(bytes, platform::compat::narf_net::TxMeta::plain()) {
        Ok(()) => 0,
        Err(()) => ENOBUFS,
    }
}

/// Family-host events: queue the work on the executor and accept it; the
/// outcome is reported when it completes.
extern "C" fn event_callback(_dev: u64, event: u32, payload: *const u8, len: usize) -> i32 {
    let bytes = if len == 0 || payload.is_null() {
        Vec::new()
    } else {
        // SAFETY: the gate lends `len` readable bytes for the call.
        unsafe { core::slice::from_raw_parts(payload, len) }.to_vec()
    };
    match event {
        wifi::EVENT_SCAN_REQUEST => {
            let Some(req) = decode_scan_request(&bytes) else {
                return EINVAL;
            };
            platform::spawn(scan_and_report(req));
            0
        }
        wifi::EVENT_CONNECT => {
            let Some(req) = decode_connect(&bytes) else {
                return EINVAL;
            };
            platform::spawn(connect_and_report(req));
            0
        }
        wifi::EVENT_DISCONNECT => {
            platform::spawn(async {
                LEAVING.store(true, Ordering::Release);
                if let Some(netdev) = super::interface::netdev() {
                    let _ = netdev.disassociate().await;
                }
                CONNECTED.store(false, Ordering::Release);
                // A disconnect while not associated still completes the
                // host's wait.
                let _ = report(
                    wifi::OP_DISCONNECTED,
                    &encode_disconnected(wifi::REASON_DEAUTH_LEAVING, true),
                );
                LEAVING.store(false, Ordering::Release);
            });
            0
        }
        // A scan runs channel by channel to completion; the result of an
        // aborted scan is simply discarded by the host.
        wifi::EVENT_SCAN_ABORT => 0,
        _ => -95,
    }
}

async fn scan_and_report(req: ScanRequest) {
    let result = match super::interface::netdev() {
        Some(netdev) => {
            let result = netdev.scan(req).await;
            result.map(|list| {
                list.into_iter()
                    .map(|bss| {
                        let ies = netdev
                            .scan_information_elements(bss.bssid)
                            .unwrap_or_default();
                        (bss, ies)
                    })
                    .collect::<Vec<_>>()
            })
        }
        None => Err(WirelessError::HardwareError),
    };
    let status = match result {
        Ok(table) => {
            *LAST_SCAN.lock() = table.iter().map(|(bss, _)| bss.clone()).collect();
            for (bss, ies) in &table {
                let _ = report(wifi::OP_SCAN_RESULT, &encode_scan_result(bss, ies));
            }
            0i32
        }
        Err(WirelessError::Busy) => -16,
        Err(_) => -5,
    };
    let _ = report(wifi::OP_SCAN_DONE, &status.to_le_bytes());
}

async fn connect_and_report(req: AssociateRequest) {
    let (bssid, frequency) = (req.bssid, req.frequency_mhz);
    let result = match (super::interface::netdev(), resolve_bss(req)) {
        (Some(netdev), Some(req)) => {
            let frequency = req.frequency_mhz;
            let target = req.bssid;
            netdev
                .associate(req)
                .await
                .map(|()| (netdev.connected_bssid().unwrap_or(target), frequency))
        }
        (None, _) => Err(WirelessError::HardwareError),
        (_, None) => Err(WirelessError::InvalidArgs),
    };
    match result {
        Ok((bssid, frequency)) => {
            CONNECTED.store(true, Ordering::Release);
            let _ = report(
                wifi::OP_CONNECT_RESULT,
                &encode_connect_result(0, bssid, frequency),
            );
        }
        Err(error) => {
            log(format_args!("connect failed: {error:?}"));
            let _ = report(
                wifi::OP_CONNECT_RESULT,
                &encode_connect_result(wifi::STATUS_UNSPECIFIED_FAILURE, bssid, frequency),
            );
        }
    }
}

/// A `CONNECT` that left the BSS to the driver (all-zero BSSID or no
/// frequency): the strongest matching network of the last scan
/// (`cfg80211_get_bss`), with the security the request asks for.
fn resolve_bss(mut req: AssociateRequest) -> Option<AssociateRequest> {
    if req.bssid != [0; 6] && req.frequency_mhz != 0 {
        return Some(req);
    }
    let wpa2 = matches!(req.security, SecurityConfig::Wpa2 { .. });
    let scan = LAST_SCAN.lock();
    let bss = scan
        .iter()
        .filter(|b| {
            if req.bssid != [0; 6] {
                b.bssid == req.bssid
            } else {
                b.ssid == req.ssid
                    && (matches!(b.security, BssSecurity::Wpa2) == wpa2)
                    && !matches!(b.security, BssSecurity::Wep | BssSecurity::Wpa)
            }
        })
        .max_by_key(|b| b.rssi)?;
    req.bssid = bss.bssid;
    req.frequency_mhz = bss.frequency_mhz;
    req.channel = freq_to_channel(bss.frequency_mhz);
    Some(req)
}

/// IEEE 802.11 channel number of a 2.4/5 GHz centre frequency.
fn freq_to_channel(mhz: u32) -> u32 {
    match mhz {
        2484 => 14,
        2412..=2472 => (mhz - 2407) / 5,
        5000..=5900 => (mhz - 5000) / 5,
        _ => 0,
    }
}

// ── Wire records (`WIFI` v2, little-endian) ───────────────────────────

fn encode_connect_result(status: u16, bssid: [u8; 6], frequency_mhz: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&status.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&bssid);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&frequency_mhz.to_le_bytes());
    out
}

fn encode_disconnected(reason: u16, local: bool) -> [u8; 4] {
    let r = reason.to_le_bytes();
    [r[0], r[1], u8::from(local), 0]
}

fn security_wire(s: BssSecurity) -> u8 {
    match s {
        BssSecurity::Open => 0,
        BssSecurity::Wep => 1,
        BssSecurity::Wpa => 2,
        BssSecurity::Wpa2 => 3,
        BssSecurity::Wpa3 => 4,
    }
}

fn encode_scan_result(bss: &BssInfo, ies: &[u8]) -> Vec<u8> {
    let ssid = &bss.ssid[..bss.ssid.len().min(32)];
    let ies = &ies[..ies.len().min(2048)];
    let mut out = Vec::with_capacity(20 + ssid.len() + ies.len());
    out.extend_from_slice(&bss.bssid);
    out.push(bss.channel.min(255) as u8);
    out.push(security_wire(bss.security));
    out.extend_from_slice(&bss.frequency_mhz.to_le_bytes());
    out.push(bss.rssi as u8);
    out.push(0);
    out.push(ssid.len() as u8);
    out.push(0);
    out.extend_from_slice(&(ies.len() as u16).to_le_bytes());
    out.extend_from_slice(ssid);
    out.extend_from_slice(ies);
    out
}

fn decode_scan_request(b: &[u8]) -> Option<ScanRequest> {
    if b.len() < 8 {
        return None;
    }
    let active = b[0] & 1 != 0;
    let (n_freq, n_ssid) = (usize::from(b[1]), usize::from(b[2]));
    let ie_len = usize::from(u16::from_le_bytes([b[4], b[5]]));
    let mut at = 8;
    let mut frequencies_mhz = Vec::with_capacity(n_freq);
    for _ in 0..n_freq {
        let f = b.get(at..at + 4)?;
        frequencies_mhz.push(u32::from_le_bytes([f[0], f[1], f[2], f[3]]));
        at += 4;
    }
    let mut ssids = Vec::with_capacity(n_ssid);
    for _ in 0..n_ssid {
        let len = usize::from(*b.get(at)?);
        ssids.push(b.get(at + 1..at + 1 + len)?.to_vec());
        at += 1 + len;
    }
    let extra_ies = b.get(at..at + ie_len)?.to_vec();
    Some(ScanRequest {
        ssids,
        frequencies_mhz,
        channels: Vec::new(),
        active,
        random_mac: None,
        colocated_6ghz: false,
        duration_tu: None,
        duration_mandatory: false,
        extra_ies,
    })
}

fn decode_connect(b: &[u8]) -> Option<AssociateRequest> {
    if b.len() < 20 {
        return None;
    }
    let mut bssid = [0u8; 6];
    bssid.copy_from_slice(&b[..6]);
    let security = b[6];
    let frequency_mhz = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
    let ssid_len = usize::from(b[12]);
    let ie_len = usize::from(u16::from_le_bytes([b[14], b[15]]));
    let secret_len = usize::from(u16::from_le_bytes([b[16], b[17]]));
    let ssid = b.get(20..20 + ssid_len)?.to_vec();
    let ie = b.get(20 + ssid_len..20 + ssid_len + ie_len)?.to_vec();
    let secret = b.get(20 + ssid_len + ie_len..20 + ssid_len + ie_len + secret_len)?;
    // Open or WPA2-PSK from a PMK: what the station's in-driver supplicant
    // runs. SAE is not advertised, so the host never sends it.
    let security = match security {
        wifi::SECURITY_OPEN => SecurityConfig::Open,
        wifi::SECURITY_PSK => SecurityConfig::Wpa2 {
            psk: secret.try_into().ok()?,
        },
        _ => return None,
    };
    Some(AssociateRequest {
        bssid,
        ssid,
        frequency_mhz,
        channel: freq_to_channel(frequency_mhz),
        security,
        ie,
    })
}

/// `REGISTER_WIPHY` from the attached generation's wireless info (what the
/// built-in nl80211 `GET_WIPHY` renders). `None` without a permitted channel.
fn encode_register_wiphy(ifindex: u32, info: &WirelessIfaceInfo) -> Option<Vec<u8>> {
    let bands: Vec<(u32, Vec<u8>)> = info
        .bands
        .iter()
        .filter_map(|band| {
            // The host keys bands by a representative frequency.
            let freq = if band.freq_mhz < 3000 { 2412 } else { 5180 };
            let channels: Vec<u8> = band
                .channels
                .iter()
                .filter(|c| (1..=233).contains(*c))
                .take(64)
                .map(|c| *c as u8)
                .collect();
            (!channels.is_empty()).then_some((freq, channels))
        })
        .collect();
    if bands.is_empty() {
        return None;
    }
    let ciphers = [narf_wireless::CIPHER_SUITE_CCMP];
    let hw = u8::from(info.hw_caps.ht_supported);
    let mut out = Vec::new();
    out.extend_from_slice(&ifindex.to_le_bytes());
    out.extend_from_slice(&info.base_mac);
    out.extend_from_slice(&1u32.to_le_bytes()); // STATION
    out.push(hw);
    out.push(ciphers.len() as u8);
    out.push(bands.len() as u8);
    out.push(wifi::FLAG_PSK_OFFLOAD | wifi::FLAG_REPORTS_DISCONNECT);
    out.push(4); // max scan SSIDs (the built-in netdev's)
    out.push(0);
    out.extend_from_slice(&0u16.to_le_bytes()); // no extra scan IEs
    for c in ciphers {
        out.extend_from_slice(&c.to_le_bytes());
    }
    for (freq, list) in &bands {
        out.extend_from_slice(&freq.to_le_bytes());
        out.push(list.len() as u8);
        out.push(0);
        out.extend_from_slice(list);
    }
    Some(out)
}
