// SPDX-License-Identifier: GPL-2.0-or-later
//! The module build's netdev and wiphy (`rtl.ko`), for either driver.
//!
//! Built in, a published station (rtlwifi's native PCIe device, rtl8xxxu's
//! RTL8188EU / gen2 USB device) registers with the kernel's net and wireless
//! registries, and nl80211 drives it through `WirelessNetIface`. A module
//! reaches the stack only through the netif bridge and the `WIFI` family
//! host (`wireless/src/module_host.rs`, version 2), so this drives the same
//! device, call for call:
//!
//! - **netdev** — `narf_netif_register_with_context` (named `wlan%d`
//!   because the device has a wireless session). TX frames arrive in
//!   [`tx_callback`] and enter the device through its own send hook (the
//!   built-in netdev's). RX: the device's drain calls
//!   `platform::net::iface::on_rx_frame_from`, which lands in [`rx`] and goes
//!   out through `narf_netif_rx`.
//! - **wiphy** — `REGISTER_WIPHY` from the device's own
//!   `get_wireless_info`, `cipher_suites` and offload answers.
//! - **control** — the host's `SCAN_REQUEST` / `CONNECT` / `DISCONNECT`
//!   events run the device's `WirelessNetIface::scan` / `associate` /
//!   `disassociate` (the in-driver WPA2-PSK supplicant) on the module's
//!   executor and report `SCAN_RESULT` / `SCAN_DONE` / `CONNECT_RESULT` /
//!   `DISCONNECTED`. An unsolicited link loss (`nl80211::notify_disconnect`
//!   built in) is reported as `DISCONNECTED` ([`disconnected`]).
//!
//! A function whose native station is not retained is the built-in
//! diagnostic profile: [`publish_diagnostic`] registers its netdev and a
//! wiphy without an event channel, so the host answers scan and connect with
//! `NotSupported` exactly as the built-in diagnostic `WirelessNetIface` does.
//! One netdev per module (the bridge's TX callback carries no identity).

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use narf_wireless::scan::BssSecurity;
use narf_wireless::{AssociateRequest, BssInfo, ScanRequest, SecurityConfig, WirelessError};

use crate::platform::wireless::WirelessNetIface;
use crate::platform::{self, Console, IrqSafeSpinLock};

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
        pub fn narf_usb_netif_register_with_context(
            dev: u64,
            mac: *const u8,
            tx_callback: usize,
            out_ifindex: *mut u32,
        ) -> i32;
        pub fn narf_usb_netif_rx(dev: u64, ifindex: u32, frame: *mut u8, len: usize) -> i32;
        pub fn narf_wireless_open(
            dev: u64,
            family: u32,
            version: u32,
            out_session: *mut u64,
        ) -> i32;
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
    /// `WirelessModes::STATION`.
    pub const MODE_STATION: u32 = 1;
    /// IEEE 802.11 status: unspecified failure.
    pub const STATUS_UNSPECIFIED_FAILURE: u16 = 1;
    /// `WLAN_REASON_DEAUTH_LEAVING`.
    pub const REASON_DEAUTH_LEAVING: u16 = 3;
}

const ENOBUFS: i32 = -105;
const ENODEV: i32 = -19;
const EINVAL: i32 = -22;
const EOPNOTSUPP: i32 = -95;

/// A published station, as the module drives it.
type Station = dyn WirelessNetIface;
/// The station's own TX entry (the built-in netdev's send hook).
pub type Send = alloc::boxed::Box<dyn Fn(&[u8]) -> Result<(), ()> + core::marker::Send + Sync>;

/// What publication registered, for the probe log.
#[derive(Clone, Copy, Debug)]
pub struct Published {
    pub ifindex: u32,
    pub session: u64,
}

/// Why publication stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The family host refused a session (errno).
    Session(i32),
    /// The netif bridge refused the netdev (errno).
    Netdev(i32),
    /// The host refused the wiphy record (errno).
    Wiphy(i32),
}

/// The bound netdev (one function per module).
struct Netdev {
    ifindex: u32,
    /// A USB function: the `narf_usb_netif_*` exports, and no wiphy.
    usb: bool,
    session: u64,
    /// The station's TX entry (none: diagnostic).
    send: Option<Send>,
    device: Option<Arc<Station>>,
    /// Carrier, as the device reports it.
    up: AtomicBool,
    /// Centre frequency of the current association.
    frequency: AtomicU32,
    /// The last scan's networks, for a `CONNECT` without a BSSID.
    last_scan: IrqSafeSpinLock<Vec<BssInfo>>,
}

static NETDEV: IrqSafeSpinLock<Option<Arc<Netdev>>> = IrqSafeSpinLock::new(None);

fn netdev() -> Option<Arc<Netdev>> {
    NETDEV.lock().clone()
}

fn log(args: core::fmt::Arguments<'_>) {
    let _ = writeln!(Console, "  rtl.ko: {}", args);
}

/// Submit one record to the family host and collect its status (every v2
/// opcode completes at submit).
fn report(session: u64, opcode: u32, request: &[u8]) -> i32 {
    let dev = platform::device();
    let mut op = 0u64;
    // SAFETY: `request` names `len` readable bytes; `op` is a live local.
    let rc = unsafe {
        ffi::narf_wireless_submit(
            dev,
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
    unsafe { ffi::narf_wireless_poll(dev, session, op, reply.as_mut_ptr(), reply.len(), &mut len) }
}

// ── Hooks the platform forwards the device's kernel calls to ──────────

/// `narf_net::iface::on_rx_frame_from`: hand one received Ethernet frame to
/// the stack. The device's internal RX ring has no consumer in the module
/// (frames go out here), so its consumer side is dropped.
pub(crate) fn rx(_name: &str, bytes: &mut [u8]) {
    let Some(netdev) = netdev() else {
        return;
    };
    if let Some(device) = &netdev.device {
        drop(device.rx_ring().lock().take());
    }
    let (dev, ifindex, frame, len) = (
        platform::device(),
        netdev.ifindex,
        bytes.as_mut_ptr(),
        bytes.len(),
    );
    // SAFETY: `frame` names `len` bytes the call may rewrite in place.
    let _ = unsafe {
        if netdev.usb {
            ffi::narf_usb_netif_rx(dev, ifindex, frame, len)
        } else {
            ffi::narf_netif_rx(dev, ifindex, frame, len)
        }
    };
}

/// `narf_net::iface::set_link_metadata`: carrier follows the association.
pub(crate) fn link(_name: &str, up: bool) {
    if let Some(netdev) = netdev() {
        netdev.up.store(up, Ordering::Release);
    }
}

/// `nl80211::notify_disconnect`: an unsolicited link loss.
pub(crate) fn disconnected(_name: &str, reason: u16, local: bool) {
    if let Some(netdev) = netdev() {
        netdev.frequency.store(0, Ordering::Release);
        if netdev.usb {
            log(format_args!("link lost (reason {reason})"));
            return;
        }
        let _ = report(
            netdev.session,
            wifi::OP_DISCONNECTED,
            &encode_disconnected(reason, local),
        );
    }
}

/// The device withdrew from its registries (removal or terminal failure).
pub(crate) fn withdraw() {
    if let Some(netdev) = netdev() {
        netdev.up.store(false, Ordering::Release);
    }
}

// ── Netif callbacks ───────────────────────────────────────────────────

/// Netif TX: the stack lends one Ethernet frame; the device's own send
/// hook (`interface::send`, the built-in netdev's) admits or refuses it.
extern "C" fn tx_callback(_dev: u64, frame: *const u8, len: usize) -> i32 {
    let Some(netdev) = netdev() else {
        return ENODEV;
    };
    let Some(send) = &netdev.send else {
        return ENOBUFS;
    };
    if frame.is_null() || len < 14 {
        return ENOBUFS;
    }
    // SAFETY: the bridge lends `len` readable bytes for the call.
    let bytes = unsafe { core::slice::from_raw_parts(frame, len) };
    match send(bytes) {
        Ok(()) => {
            platform::run_executor();
            0
        }
        Err(()) => ENOBUFS,
    }
}

/// Family-host events: queue the work on the executor and accept it; the
/// outcome is reported when it completes.
extern "C" fn event_callback(_dev: u64, event: u32, payload: *const u8, len: usize) -> i32 {
    let Some(netdev) = netdev() else {
        return ENODEV;
    };
    let Some(device) = netdev.device.clone() else {
        return ENODEV;
    };
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
            platform::scheduler::spawn(async move {
                scan_and_report(&netdev, device.as_ref(), req).await
            });
            0
        }
        wifi::EVENT_CONNECT => {
            let Some(req) = decode_connect(&bytes) else {
                return EINVAL;
            };
            platform::scheduler::spawn(async move {
                connect_and_report(&netdev, device.as_ref(), req).await
            });
            0
        }
        wifi::EVENT_DISCONNECT => {
            platform::scheduler::spawn(async move {
                let _ = device.disassociate().await;
                netdev.frequency.store(0, Ordering::Release);
                // A disconnect while not associated still completes the
                // host's wait.
                let _ = report(
                    netdev.session,
                    wifi::OP_DISCONNECTED,
                    &encode_disconnected(wifi::REASON_DEAUTH_LEAVING, true),
                );
            });
            0
        }
        // The device's scan has no cancellation hook; the host discards an
        // aborted scan's results.
        wifi::EVENT_SCAN_ABORT => 0,
        _ => EOPNOTSUPP,
    }
}

async fn scan_and_report(netdev: &Netdev, device: &Station, req: ScanRequest) {
    let status = match device.scan(req).await {
        Ok(results) => {
            for bss in &results {
                let ies = device
                    .scan_information_elements(bss.bssid)
                    .unwrap_or_default();
                let _ = report(
                    netdev.session,
                    wifi::OP_SCAN_RESULT,
                    &encode_scan_result(bss, &ies),
                );
            }
            *netdev.last_scan.lock() = results;
            0i32
        }
        Err(WirelessError::Busy) => -16,
        Err(_) => -5,
    };
    let _ = report(netdev.session, wifi::OP_SCAN_DONE, &status.to_le_bytes());
}

/// A `CONNECT` that left the BSS to the driver (all-zero BSSID): the
/// strongest matching network of the last scan (`cfg80211_get_bss`).
fn resolve_bss(netdev: &Netdev, mut req: AssociateRequest) -> Option<AssociateRequest> {
    if req.bssid != [0; 6] && req.frequency_mhz != 0 {
        return Some(req);
    }
    let protected = !matches!(req.security, SecurityConfig::Open);
    let scan = netdev.last_scan.lock();
    let bss = scan
        .iter()
        .filter(|b| (req.bssid == [0; 6] || b.bssid == req.bssid) && b.ssid == req.ssid)
        .filter(|b| matches!(b.security, BssSecurity::Open) != protected)
        .max_by_key(|b| b.rssi)?;
    req.bssid = bss.bssid;
    req.frequency_mhz = bss.frequency_mhz;
    req.channel = bss.channel;
    Some(req)
}

async fn connect_and_report(netdev: &Netdev, device: &Station, req: AssociateRequest) {
    let (bssid, frequency) = (req.bssid, req.frequency_mhz);
    let result = match resolve_bss(netdev, req) {
        Some(req) => {
            let frequency = req.frequency_mhz;
            device.associate(req).await.map(|()| frequency)
        }
        None => Err(WirelessError::InvalidArgs),
    };
    match (result, device.connected_bssid()) {
        (Ok(frequency), Some(bssid)) => {
            netdev.frequency.store(frequency, Ordering::Release);
            let _ = report(
                netdev.session,
                wifi::OP_CONNECT_RESULT,
                &encode_connect_result(0, bssid, frequency),
            );
        }
        (result, _) => {
            log(format_args!("connect failed: {:?}", result.err()));
            let _ = report(
                netdev.session,
                wifi::OP_CONNECT_RESULT,
                &encode_connect_result(wifi::STATUS_UNSPECIFIED_FAILURE, bssid, frequency),
            );
        }
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

/// 2.4/5 GHz centre frequency to channel number.
fn freq_to_channel(mhz: u32) -> u32 {
    match mhz {
        2484 => 14,
        2412..=2472 => (mhz - 2407) / 5,
        5000..=5900 => (mhz - 5000) / 5,
        _ => 0,
    }
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
    // The driver's in-driver SME offloads PSK only (`supports_sae_offload`
    // is not advertised), so an SAE request is refused here.
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

/// `REGISTER_WIPHY` (`decode_register_wiphy` layout) from the device's
/// own answers: its bands and HT/VHT capabilities, cipher suites and SME
/// offloads. The diagnostic profile has none of those: station mode on the
/// 2.4 GHz channels 1-11 the native station scans.
/// A wiphy band: representative frequency and channel numbers.
type Band = (u32, Vec<u8>);

fn encode_register_wiphy(ifindex: u32, mac: [u8; 6], device: Option<&Station>) -> Vec<u8> {
    let (bands, hw, ciphers, flags): (Vec<Band>, u8, &[u32], u8) = match device {
        Some(device) => {
            let info = device.get_wireless_info();
            let bands = info
                .bands
                .iter()
                .filter(|band| !band.channels.is_empty())
                .map(|band| {
                    let channels = band
                        .channels
                        .iter()
                        .filter(|&&c| (1..=233).contains(&c))
                        .map(|&c| c as u8)
                        .take(64)
                        .collect();
                    (band.freq_mhz, channels)
                })
                .collect();
            let mut hw = 0u8;
            if info.hw_caps.ht_supported {
                hw |= 1;
            }
            if info.hw_caps.vht_supported {
                hw |= 2;
            }
            let mut flags = 0u8;
            if device.supports_handshake_offload() {
                flags |= wifi::FLAG_PSK_OFFLOAD;
            }
            if device.reports_disconnect_events() {
                flags |= wifi::FLAG_REPORTS_DISCONNECT;
            }
            (bands, hw, device.cipher_suites(), flags)
        }
        None => (alloc::vec![(2412, (1..=11).collect())], 0, &[], 0),
    };
    let mut out = Vec::new();
    out.extend_from_slice(&ifindex.to_le_bytes());
    out.extend_from_slice(&mac);
    out.extend_from_slice(&wifi::MODE_STATION.to_le_bytes());
    out.push(hw);
    out.push(ciphers.len().min(8) as u8);
    out.push(bands.len() as u8);
    out.push(flags);
    let (max_ssids, max_ie) =
        device.map_or((0, 512), |d| (d.max_scan_ssids(), d.max_scan_ie_len()));
    out.push(max_ssids.min(16));
    out.push(0);
    out.extend_from_slice(&max_ie.min(2048).to_le_bytes());
    for c in ciphers.iter().take(8) {
        out.extend_from_slice(&c.to_le_bytes());
    }
    for (freq, channels) in &bands {
        out.extend_from_slice(&freq.to_le_bytes());
        out.push(channels.len() as u8);
        out.push(0);
        out.extend_from_slice(channels);
    }
    out
}

/// Session, netdev (`wlan%d`), then its wiphy.
fn register(
    mac: [u8; 6],
    device: Option<Arc<Station>>,
    send: Option<Send>,
) -> Result<Published, Error> {
    let dev = platform::device();
    let mut session = 0u64;
    let rc = if device.is_some() {
        // SAFETY: `event_callback` is a valid extern "C" fn in this image;
        // `session` is a live local.
        unsafe {
            ffi::narf_wireless_open_with_event(
                dev,
                wifi::FAMILY,
                wifi::VERSION,
                event_callback as usize,
                &mut session,
            )
        }
    } else {
        // SAFETY: `session` is a live local.
        unsafe { ffi::narf_wireless_open(dev, wifi::FAMILY, wifi::VERSION, &mut session) }
    };
    if rc != 0 {
        return Err(Error::Session(rc));
    }
    let mut ifindex = 0u32;
    // SAFETY: `mac` names six readable bytes; `tx_callback` is a valid
    // extern "C" fn in this image; `ifindex` is a live local.
    let rc = unsafe {
        ffi::narf_netif_register_with_context(dev, mac.as_ptr(), tx_callback as usize, &mut ifindex)
    };
    if rc != 0 {
        return Err(Error::Netdev(rc));
    }
    let wiphy = encode_register_wiphy(ifindex, mac, device.as_deref());
    *NETDEV.lock() = Some(Arc::new(Netdev {
        ifindex,
        usb: false,
        session,
        send,
        device,
        up: AtomicBool::new(false),
        frequency: AtomicU32::new(0),
        last_scan: IrqSafeSpinLock::new(Vec::new()),
    }));
    let rc = report(session, wifi::OP_REGISTER_WIPHY, &wiphy);
    if rc != 0 {
        log(format_args!("wiphy registration refused ({rc})"));
        return Err(Error::Wiphy(rc));
    }
    Ok(Published { ifindex, session })
}

/// Publish a function without a retained native station: the built-in
/// diagnostic profile (scan and connect answer `NotSupported`; TX refused).
pub fn publish_diagnostic(mac: [u8; 6]) -> Result<Published, Error> {
    register(mac, None, None)
}

/// A station's publication in the module (the drivers' `publish` /
/// `attach`): its netdev and wiphy, TX entering through `send`.
pub(crate) fn attach(device: Arc<Station>, send: Send) -> Result<Published, Error> {
    if netdev().is_some() {
        return Err(Error::Netdev(-16));
    }
    let mac = device.mac();
    let published = register(mac, Some(device), Some(send))?;
    log(format_args!(
        "native station published (ifindex {})",
        published.ifindex
    ));
    Ok(published)
}

/// The netdev's name in logs.
pub fn describe() -> String {
    netdev().map_or_else(
        || String::from("wlan?"),
        |n| alloc::format!("wlan (ifindex {})", n.ifindex),
    )
}

// ── USB stations (rtl8xxxu) ───────────────────────────────────────────

/// A USB station's publication: its netdev through the USB netif bridge
/// (`narf_usb_netif_register_with_context`), TX entering through `send`.
///
/// A USB function has no wiphy: the `WIFI` host binds a session to a bus
/// device context's `Cap<BusDeviceCap>`, which a USB function does not
/// have. So nl80211 cannot drive it. The driver's own SME is driven instead
/// by the module's parameters (`rtl.ssid=`, `rtl.psk=` / `rtl.passphrase=`),
/// as `rtw88.ko` does: [`autoconnect`] scans for the SSID and associates
/// through the station's own `WirelessNetIface` methods, and reconnects
/// after a link loss.
pub(crate) fn attach_usb(device: Arc<Station>, send: Send) -> Result<Published, Error> {
    if netdev().is_some() {
        return Err(Error::Netdev(-16));
    }
    let mac = device.mac();
    let mut ifindex = 0u32;
    // SAFETY: `mac` names six readable bytes; `tx_callback` is a valid
    // extern "C" fn in this image; `ifindex` is a live local.
    let rc = unsafe {
        ffi::narf_usb_netif_register_with_context(
            platform::device(),
            mac.as_ptr(),
            tx_callback as usize,
            &mut ifindex,
        )
    };
    if rc != 0 {
        return Err(Error::Netdev(rc));
    }
    let netdev = Arc::new(Netdev {
        ifindex,
        usb: true,
        session: 0,
        send: Some(send),
        device: Some(device.clone()),
        up: AtomicBool::new(false),
        frequency: AtomicU32::new(0),
        last_scan: IrqSafeSpinLock::new(Vec::new()),
    });
    *NETDEV.lock() = Some(netdev.clone());
    log(format_args!(
        "USB station published (ifindex {ifindex}; no wiphy)"
    ));
    platform::scheduler::spawn(autoconnect(netdev, device));
    Ok(Published {
        ifindex,
        session: 0,
    })
}

/// A load parameter's value, empty when not given.
fn param(name: &str) -> String {
    narf_module_rt::param::get(name).unwrap_or_default()
}

/// 64 hex digits as a 32-byte PSK.
fn hex_psk(text: &str) -> Option<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut psk = [0u8; 32];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        let hi = char::from(pair[0]).to_digit(16)?;
        let lo = char::from(pair[1]).to_digit(16)?;
        psk[i] = (hi * 16 + lo) as u8;
    }
    Some(psk)
}

/// The station's security from the parameters: a hex PSK, else a WPA2
/// passphrase (8-63 bytes, PBKDF2 over the SSID), else open.
fn security_from_params(ssid: &[u8]) -> Option<SecurityConfig> {
    let psk = param("psk");
    if !psk.is_empty() {
        return hex_psk(&psk).map(|psk| SecurityConfig::Wpa2 { psk });
    }
    let passphrase = param("passphrase");
    if !passphrase.is_empty() {
        if !(8..=63).contains(&passphrase.len()) {
            return None;
        }
        let psk = narf_crypto::pbkdf2_sha1::wpa2_pmk(passphrase.as_bytes(), ssid);
        return Some(SecurityConfig::Wpa2 { psk });
    }
    Some(SecurityConfig::Open)
}

/// Retry interval of the parameter-driven SME.
const AUTOCONNECT_RETRY_NS: u64 = 5_000_000_000;

async fn autoconnect(netdev: Arc<Netdev>, device: Arc<Station>) {
    let ssid = param("ssid");
    if ssid.is_empty() {
        log(format_args!(
            "no rtl.ssid= given; the USB station stays idle"
        ));
        return;
    }
    let ssid = ssid.into_bytes();
    // Derived once: a passphrase's PBKDF2 is the expensive part.
    let psk = match security_from_params(&ssid) {
        Some(SecurityConfig::Wpa2 { psk }) => Some(psk),
        Some(_) => None,
        None => {
            log(format_args!(
                "ignoring rtl.psk= / rtl.passphrase=: malformed"
            ));
            return;
        }
    };
    loop {
        if device.connected_bssid().is_none() {
            let request = ScanRequest {
                ssids: alloc::vec![ssid.clone()],
                frequencies_mhz: Vec::new(),
                channels: Vec::new(),
                active: true,
                random_mac: None,
                colocated_6ghz: false,
                duration_tu: None,
                duration_mandatory: false,
                extra_ies: Vec::new(),
            };
            match device.scan(request).await {
                Ok(results) => *netdev.last_scan.lock() = results,
                Err(error) => log(format_args!("autoconnect scan failed: {error:?}")),
            }
            let request = AssociateRequest {
                bssid: [0; 6],
                ssid: ssid.clone(),
                frequency_mhz: 0,
                channel: 0,
                security: match psk {
                    Some(psk) => SecurityConfig::Wpa2 { psk },
                    None => SecurityConfig::Open,
                },
                ie: Vec::new(),
            };
            match resolve_bss(&netdev, request) {
                Some(request) => {
                    let frequency = request.frequency_mhz;
                    match device.associate(request).await {
                        Ok(()) => {
                            netdev.frequency.store(frequency, Ordering::Release);
                            log(format_args!("associated ({frequency} MHz)"));
                        }
                        Err(error) => log(format_args!("autoconnect failed: {error:?}")),
                    }
                }
                None => log(format_args!("autoconnect: SSID not found")),
            }
        }
        platform::time::sleep_cycles(AUTOCONNECT_RETRY_NS).await;
    }
}
