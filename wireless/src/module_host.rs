//! Native wireless family host (family `WIFI`, version 2).
//!
//! The cfg80211 glue that makes Wi-Fi `.ko` datapaths work. A loadable
//! driver owns its probe device, its chip and its station state machine
//! (including the supplicant, as ath11k's in-driver SME does); the native side
//! owns the 802.11 control plane — the wiphy record nl80211 renders and the
//! [`WirelessNetIface`] shell nl80211 drives — and the per-session event
//! channel to the module. Frames never pass through the host: they flow
//! through the module's netdev (`narf_netif_register_with_context` /
//! `narf_netif_rx`), which the netif bridge names `wlan%d` for a device with a
//! wireless session.
//!
//! ## Protocol
//!
//! Module → native, through `narf_wireless_submit` + `narf_wireless_poll`
//! (every opcode completes synchronously at submit; the poll only collects
//! the reply and frees the operation slot):
//!
//! | Opcode | Request | Reply |
//! |---|---|---|
//! | `REGISTER_WIPHY` | wiphy record bound to the module's netdev (see [`decode_register_wiphy`]) | wiphy index u32 |
//! | `SCAN_RESULT` | one BSS and its IEs ([`decode_scan_result`]) | empty |
//! | `SCAN_DONE` | status i32 (0, or a negative errno for an aborted scan) | empty |
//! | `CONNECT_RESULT` | 802.11 status, BSSID, frequency ([`decode_connect_result`]) | empty |
//! | `DISCONNECTED` | reason u16, locally-generated u8, reserved u8 | empty |
//!
//! Native → module, through the session's event callback (registered by
//! `narf_wireless_open_with_event`; the callback's return is the module's
//! acceptance, the outcome arrives later as one of the reports above):
//!
//! | Event | Payload |
//! |---|---|
//! | `SCAN_REQUEST` | [`encode_scan_request`] |
//! | `CONNECT` | [`encode_connect`] — Open, a PSK/PMK, or an SAE password |
//! | `DISCONNECT` | reason u16, reserved u16 |
//! | `SCAN_ABORT` | empty |
//!
//! The shell advertises the module's SME offloads (`flags`), so nl80211's
//! CONNECT hands a PSK (`NL80211_ATTR_PMK`) or SAE password straight to
//! [`WirelessNetIface::associate`] and through `CONNECT` to the module's
//! supplicant — the same split as a FullMAC driver. A userspace SME
//! (`SecurityConfig::External`, AUTHENTICATE/ASSOCIATE, control-port EAPOL)
//! is not carried by this version and is refused.
//!
//! Lifetime rules (same contract as every `module_wireless::Host`): hosts
//! are kernel-resident — no hook points into unloadable text. The module's
//! event callback is stored in the session, invoked only through the bus
//! call gate (which pins the live module and enters its effective domain),
//! and forgotten when the session closes or the device is retired. Requests
//! and replies are bounded copies (`MAX_REQUEST` / `MAX_REPLY`); no Rust
//! object, firmware pointer, DMA pointer or future crosses the boundary.
//!
//! Perf class: no hot path — bring-up, scan, connect and link-loss rates.

use crate::{
    iface::{HwCaps, WirelessBand, WirelessIfaceInfo, WirelessModes},
    registry,
    scan::{BssInfo, BssSecurity, ScanRequest},
    AssociateRequest, SecurityConfig, WirelessConfig, WirelessError, WirelessNetIface,
};
use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use async_trait::async_trait;
use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    task::{Context, Poll, Waker},
};
use narf_bus::{BusDevice, BusDeviceCap, ModuleWirelessEventFn};
use narf_capabilities::{Cap, CapError, CapOp, Write};
use narf_ipc::{Consumer, Producer};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};

/// Family id for the generic Wi-Fi protocol: ASCII `"wifi"`. Distinct from
/// the mt76 private family (`0x6d74_3736`, `"mt76"`); `register` refuses a
/// second host for the same family, so the two hosts coexist.
pub const FAMILY_WIFI: u32 = 0x7769_6669;
/// Protocol version. Extended by bumping the version, never by silently
/// repurposing an opcode. Version 2 binds the wiphy to the module's netdev
/// and carries the station control plane.
pub const VERSION: u32 = 2;

/// Module → native opcodes.
pub const OP_REGISTER_WIPHY: u32 = 0x01;
pub const OP_SCAN_RESULT: u32 = 0x02;
pub const OP_SCAN_DONE: u32 = 0x03;
pub const OP_CONNECT_RESULT: u32 = 0x04;
pub const OP_DISCONNECTED: u32 = 0x05;

/// Native → module events (a separate namespace from the opcodes).
pub const EVENT_SCAN_REQUEST: u32 = 0x01;
pub const EVENT_CONNECT: u32 = 0x02;
pub const EVENT_DISCONNECT: u32 = 0x03;
pub const EVENT_SCAN_ABORT: u32 = 0x04;

/// `REGISTER_WIPHY` flags: the module's SME offloads.
/// The module runs the WPA2 4-way handshake from a supplied PMK.
pub const FLAG_PSK_OFFLOAD: u8 = 0x01;
/// The module runs WPA3-SAE from a supplied password.
pub const FLAG_SAE_OFFLOAD: u8 = 0x02;
/// The module reports link loss and local teardown as `DISCONNECTED`.
pub const FLAG_REPORTS_DISCONNECT: u8 = 0x04;
const KNOWN_FLAGS: u8 = FLAG_PSK_OFFLOAD | FLAG_SAE_OFFLOAD | FLAG_REPORTS_DISCONNECT;

/// `CONNECT` security selector.
pub const SECURITY_OPEN: u8 = 0;
/// `secret` is the 32-byte PMK (WPA2-PSK).
pub const SECURITY_PSK: u8 = 1;
/// `secret` is the SAE password (WPA3-Personal), 1..=63 bytes... or longer:
/// SAE passwords are not bounded by the WPA2 passphrase rule.
pub const SECURITY_SAE: u8 = 2;

/// Wire limits.
const MAX_CIPHERS: usize = 8;
const MAX_BANDS: usize = 3;
const MAX_CHANNELS_PER_BAND: usize = 64;
const MAX_CHANNEL_NUMBER: u32 = 233;
const MAX_SCAN_SSIDS: u8 = 16;
const MAX_SCAN_IE_LEN: u16 = 2048;
const MAX_SSID: usize = 32;
const MAX_BSS_IES: usize = 2048;
const MAX_SAE_PASSWORD: usize = 256;
/// Scan results a single scan keeps; a module flooding results past this is
/// refused rather than grown without bound.
const MAX_SCAN_RESULTS: usize = 256;

/// How long a shell operation waits for the module's report.
const SCAN_TIMEOUT_MS: u64 = 15_000;
/// SAE plus the 4-way handshake on a slow AP takes seconds.
const CONNECT_TIMEOUT_MS: u64 = 20_000;
const DISCONNECT_TIMEOUT_MS: u64 = 3_000;
/// Re-check cadence while waiting for a report.
const WAIT_SLICE_MS: u64 = 10;

/// Stable wiphy ids minted by this host live in this range so they can
/// never collide with the builtin drivers' FNV-1a(name) ids, and never
/// overlap the control-wdev space (bit 63).
const MODULE_WIPHY_ID_BASE: u64 = 1 << 62;

static SESSIONS: IrqSafeSpinLock<Vec<Arc<Session>>> = IrqSafeSpinLock::new(Vec::new());
static NEXT_OPERATION: AtomicU64 = AtomicU64::new(1);
static NEXT_WIPHY: AtomicU64 = AtomicU64::new(0);
/// Serialises wiphy registration (name check + `registry::register`) so two
/// concurrent `REGISTER_WIPHY` submissions can never publish the same name.
static REGISTER_GUARD: IrqSafeSpinLock<()> = IrqSafeSpinLock::new(());

/// Cipher suites a module may advertise.
const KNOWN_CIPHERS: &[u32] = &[
    crate::CIPHER_SUITE_TKIP,
    crate::CIPHER_SUITE_CCMP,
    crate::CIPHER_SUITE_AES_CMAC,
    crate::CIPHER_SUITE_GCMP,
    crate::CIPHER_SUITE_GCMP_256,
    crate::CIPHER_SUITE_CCMP_256,
    crate::CIPHER_SUITE_BIP_GMAC_128,
    crate::CIPHER_SUITE_BIP_GMAC_256,
    crate::CIPHER_SUITE_BIP_CMAC_256,
];

static HOST: narf_bus::module_wireless::Host = narf_bus::module_wireless::Host {
    family: FAMILY_WIFI,
    version: VERSION,
    open,
    submit,
    poll,
    cancel,
    close,
};

#[path = "module_host_tests.rs"]
mod tests;

/// Register the generic Wi-Fi family host. Called from
/// [`crate::register_initcalls`] at boot, before any module can load.
pub fn register() {
    let _ = narf_bus::module_wireless::register(&HOST);
}

/// Deliver one native→module event to a session's callback. Returns
/// `-EOPNOTSUPP` for an unknown event, `-EMSGSIZE` for an over-bounded
/// payload, and `-ENODEV` when the session is unknown, closed, revoked, or
/// was opened without an event callback. Otherwise the callback's return:
/// whether the module accepted the event.
pub fn deliver_event(session_id: u64, event: u32, payload: &[u8]) -> i32 {
    if !matches!(
        event,
        EVENT_SCAN_REQUEST | EVENT_CONNECT | EVENT_DISCONNECT | EVENT_SCAN_ABORT
    ) {
        return -95;
    }
    if payload.len() > narf_bus::module_wireless::MAX_REQUEST {
        return -90;
    }
    let session = match session(session_id) {
        Ok(session) => session,
        Err(error) => return error,
    };
    if session.current().is_err() {
        return -19;
    }
    let Some(callback) = session.event else {
        return -19;
    };
    narf_bus::call_module_wireless_event(session.owner, callback, session.token, event, payload)
}

/// Native work behind one submitted operation. Every v2 opcode completes at
/// submit, so `future` is `None`; the slot keeps the shape that cancellation
/// and close already handle.
type NativeWork = Pin<Box<dyn Future<Output = Result<Vec<u8>, i32>> + Send>>;
struct Operation {
    id: u64,
    started: bool,
    cancelled: bool,
    future: Option<NativeWork>,
    result: Option<Result<Vec<u8>, i32>>,
}
impl Operation {
    fn advance(&mut self, cx: &mut Context<'_>) {
        if let Some(future) = self.future.as_mut() {
            self.started = true;
            if let Poll::Ready(result) = future.as_mut().poll(cx) {
                self.future = None;
                self.result = Some(if self.cancelled && result.is_ok() {
                    Err(-114)
                } else {
                    result
                });
            }
        }
    }
    fn request_cancel(&mut self) {
        self.cancelled = true;
        if !self.started {
            self.future = None;
            self.result = Some(Err(-125));
        }
    }
}

struct Session {
    id: u64,
    owner: u64,
    token: u64,
    cap: Cap<BusDeviceCap, Write>,
    closed: AtomicBool,
    /// Per-session event callback from `narf_wireless_open_with_event`.
    /// `None` for plain-open sessions. Immutable after `open`.
    event: Option<ModuleWirelessEventFn>,
    operation: Mutex<Option<Operation>>,
    /// Published wiphy shell, if this session completed `REGISTER_WIPHY`.
    wiphy: IrqSafeSpinLock<Option<Arc<ModuleWiphy>>>,
}

struct Current;
impl CapOp<BusDeviceCap, Write> for Current {
    type Output = ();
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<(), CapError> {
        Ok(())
    }
}
impl Session {
    fn current(&self) -> Result<(), i32> {
        if self.closed.load(Ordering::Acquire) {
            return Err(-19);
        }
        self.cap.invoke(Current).map_err(|_| -19)
    }
}

fn session(id: u64) -> Result<Arc<Session>, i32> {
    SESSIONS
        .lock()
        .iter()
        .find(|s| s.id == id)
        .cloned()
        .ok_or(-19)
}

/// One BSS the module reported, with its IEs for
/// [`WirelessNetIface::scan_information_elements`].
#[derive(Clone, Debug)]
struct Bss {
    info: BssInfo,
    ies: Vec<u8>,
}

/// The scan a shell `scan()` is waiting on.
#[derive(Default)]
struct PendingScan {
    results: Vec<BssInfo>,
    done: Option<i32>,
}

/// What a shell `associate()` / `disassociate()` is waiting on.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pending {
    Idle,
    Connect,
    Connected,
    Refused(u16),
    Disconnect,
    Disconnected,
}

struct ShellState {
    bssid: Option<[u8; 6]>,
    scan: Option<PendingScan>,
    /// Every BSS reported since registration, newest per BSSID.
    bss: Vec<Bss>,
    pending: Pending,
}

/// Native wiphy shell for one module session: the cfg80211-visible side of
/// the module's radio. It carries the bands/modes/caps/ciphers and SME
/// offloads the module advertised into nl80211, turns nl80211's scan,
/// connect and disconnect into events, and the module's reports back into
/// results, carrier and nl80211 notifications. Its name is the module's
/// netdev's, which is how nl80211 resolves one to the other.
pub struct ModuleWiphy {
    name: String,
    mac: [u8; 6],
    wiphy_id: u64,
    session_id: u64,
    flags: u8,
    max_scan_ssids: u8,
    max_scan_ie_len: u16,
    info: IrqSafeSpinLock<WirelessIfaceInfo>,
    /// Validated cipher suites, leaked once at registration so
    /// `cipher_suites()` can return the `&'static [u32]` the trait requires
    /// (one small slice per probe device for the process lifetime).
    ciphers: &'static [u32],
    connected: AtomicBool,
    state: IrqSafeSpinLock<ShellState>,
    rx: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}

impl ModuleWiphy {
    fn set_carrier(&self, up: bool) {
        self.connected.store(up, Ordering::Release);
        let _ = narf_net::iface::set_link_metadata(&self.name, up, None, None);
    }

    /// Wait until `done` holds or `timeout_ms` passes; `true` if it held.
    async fn wait_for(&self, timeout_ms: u64, mut done: impl FnMut(&ShellState) -> bool) -> bool {
        let deadline = narf_time::Deadline::after_ms(timeout_ms);
        loop {
            if done(&self.state.lock()) {
                return true;
            }
            if deadline.expired() {
                return false;
            }
            narf_time::sleep_ms(WAIT_SLICE_MS).await;
        }
    }

    fn report_scan_result(&self, bss: Bss) -> Result<(), i32> {
        let mut state = self.state.lock();
        if let Some(scan) = state.scan.as_mut() {
            if scan.done.is_none() {
                if scan.results.len() >= MAX_SCAN_RESULTS {
                    return Err(-28);
                }
                scan.results.retain(|r| r.bssid != bss.info.bssid);
                scan.results.push(bss.info.clone());
            }
        }
        // Driver-initiated scans (an in-driver autoconnect) feed the table
        // too, so a later CONNECT's IEs are known either way.
        state.bss.retain(|b| b.info.bssid != bss.info.bssid);
        if state.bss.len() >= MAX_SCAN_RESULTS {
            state.bss.remove(0);
        }
        state.bss.push(bss);
        Ok(())
    }

    fn report_scan_done(&self, status: i32) {
        if let Some(scan) = self.state.lock().scan.as_mut() {
            scan.done.get_or_insert(status);
        }
    }

    fn report_connect(&self, status: u16, bssid: [u8; 6]) {
        let mut state = self.state.lock();
        if status == 0 {
            state.bssid = Some(bssid);
            if state.pending == Pending::Connect {
                state.pending = Pending::Connected;
            }
            drop(state);
            self.set_carrier(true);
        } else if state.pending == Pending::Connect {
            state.pending = Pending::Refused(status);
        }
    }

    fn report_disconnect(&self, reason: u16, local: bool) {
        let (was_connected, requested) = {
            let mut state = self.state.lock();
            let requested = state.pending == Pending::Disconnect;
            if requested {
                state.pending = Pending::Disconnected;
            }
            let was = state.bssid.take().is_some();
            (was, requested)
        };
        self.set_carrier(false);
        // A link loss the SME did not ask for is reported to nl80211 the way
        // cfg80211_disconnected does; a requested one completes the SME's own
        // DISCONNECT, which nl80211 reports itself.
        if was_connected && !requested {
            crate::nl80211::notify_disconnect(&self.name, reason, !local);
        }
    }

    fn event(&self, event: u32, payload: &[u8]) -> Result<(), WirelessError> {
        match deliver_event(self.session_id, event, payload) {
            0 => Ok(()),
            -16 => Err(WirelessError::Busy),
            -19 => Err(WirelessError::NotSupported),
            _ => Err(WirelessError::HardwareError),
        }
    }
}

impl Interface for ModuleWiphy {
    fn name(&self) -> &str {
        &self.name
    }
    fn mac(&self) -> [u8; 6] {
        self.mac
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx
    }
}

/// Sends `SCAN_ABORT` if a shell scan is dropped before the module reported
/// `SCAN_DONE` (nl80211 abort, or the SME giving up), and clears the scan.
struct ScanGuard<'a>(&'a ModuleWiphy);
impl Drop for ScanGuard<'_> {
    fn drop(&mut self) {
        let unfinished = {
            let mut state = self.0.state.lock();
            let unfinished = state.scan.as_ref().is_some_and(|s| s.done.is_none());
            state.scan = None;
            unfinished
        };
        if unfinished {
            let _ = deliver_event(self.0.session_id, EVENT_SCAN_ABORT, &[]);
        }
    }
}

#[async_trait]
impl WirelessNetIface for ModuleWiphy {
    /// The stable id minted at `REGISTER_WIPHY`, not the default
    /// FNV-1a(name), so the reply index and every later lookup agree.
    fn wiphy_id(&self) -> u64 {
        self.wiphy_id
    }
    fn get_wireless_info(&self) -> WirelessIfaceInfo {
        self.info.lock().clone()
    }
    fn cipher_suites(&self) -> &'static [u32] {
        self.ciphers
    }
    fn max_scan_ssids(&self) -> u8 {
        self.max_scan_ssids
    }
    fn max_scan_ie_len(&self) -> u16 {
        self.max_scan_ie_len
    }
    fn supports_handshake_offload(&self) -> bool {
        self.flags & FLAG_PSK_OFFLOAD != 0
    }
    fn supports_sae_offload(&self) -> bool {
        self.flags & FLAG_SAE_OFFLOAD != 0
    }
    fn reports_disconnect_events(&self) -> bool {
        self.flags & FLAG_REPORTS_DISCONNECT != 0
    }
    fn connected_bssid(&self) -> Option<[u8; 6]> {
        self.state.lock().bssid
    }
    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.state
            .lock()
            .bss
            .iter()
            .find(|b| b.info.bssid == bssid)
            .map(|b| b.ies.clone())
    }

    async fn scan(&self, req: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        let payload = encode_scan_request(&req, self.max_scan_ssids, self.max_scan_ie_len)?;
        {
            let mut state = self.state.lock();
            if state.scan.is_some() {
                return Err(WirelessError::Busy);
            }
            state.scan = Some(PendingScan::default());
        }
        let guard = ScanGuard(self);
        self.event(EVENT_SCAN_REQUEST, &payload)?;
        let finished = self
            .wait_for(SCAN_TIMEOUT_MS, |state| {
                state.scan.as_ref().is_some_and(|s| s.done.is_some())
            })
            .await;
        if !finished {
            // The guard sees the scan still unfinished: it aborts it in the
            // module and clears it.
            drop(guard);
            return Err(WirelessError::Timeout);
        }
        let scan = self.state.lock().scan.take().unwrap_or_default();
        drop(guard);
        match scan.done {
            Some(0) => Ok(scan.results),
            Some(-16) => Err(WirelessError::Busy),
            _ => Err(WirelessError::HardwareError),
        }
    }

    async fn associate(&self, req: AssociateRequest) -> Result<(), WirelessError> {
        let payload = encode_connect(&req, self.flags)?;
        {
            let mut state = self.state.lock();
            if state.pending == Pending::Connect || state.pending == Pending::Disconnect {
                return Err(WirelessError::Busy);
            }
            state.pending = Pending::Connect;
        }
        if let Err(error) = self.event(EVENT_CONNECT, &payload) {
            self.state.lock().pending = Pending::Idle;
            return Err(error);
        }
        let reported = self
            .wait_for(CONNECT_TIMEOUT_MS, |state| state.pending != Pending::Connect)
            .await;
        let outcome = core::mem::replace(&mut self.state.lock().pending, Pending::Idle);
        match outcome {
            Pending::Connected => Ok(()),
            Pending::Refused(_) => Err(WirelessError::Denied),
            _ if !reported => {
                // Abandon the attempt so the module does not finish it later.
                let _ = self.event(EVENT_DISCONNECT, &encode_disconnect(3));
                Err(WirelessError::Timeout)
            }
            _ => Err(WirelessError::HardwareError),
        }
    }

    async fn disassociate(&self) -> Result<(), WirelessError> {
        if self.state.lock().bssid.is_none() {
            return Ok(());
        }
        self.state.lock().pending = Pending::Disconnect;
        // WLAN_REASON_DEAUTH_LEAVING.
        if self.event(EVENT_DISCONNECT, &encode_disconnect(3)).is_ok() {
            let _ = self
                .wait_for(DISCONNECT_TIMEOUT_MS, |state| {
                    state.pending == Pending::Disconnected
                })
                .await;
        }
        // Whatever the module managed, the SME's view is now disconnected.
        {
            let mut state = self.state.lock();
            state.pending = Pending::Idle;
            state.bssid = None;
        }
        self.set_carrier(false);
        Ok(())
    }

    async fn set_config(&self, _cfg: WirelessConfig) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
}

/// Decoded `REGISTER_WIPHY`.
#[derive(Debug, PartialEq, Eq)]
struct RegisterWiphy {
    ifindex: u32,
    mac: [u8; 6],
    bands: Vec<WirelessBand>,
    modes: WirelessModes,
    hw_caps: HwCaps,
    flags: u8,
    max_scan_ssids: u8,
    max_scan_ie_len: u16,
    ciphers: Vec<u32>,
}

fn take_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, i32> {
    let byte = bytes.get(*cursor).ok_or(-22)?;
    *cursor += 1;
    Ok(*byte)
}
fn take_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, i32> {
    let end = cursor.checked_add(2).ok_or(-22)?;
    let chunk = bytes.get(*cursor..end).ok_or(-22)?;
    *cursor = end;
    chunk.try_into().map(u16::from_le_bytes).map_err(|_| -22)
}
fn take_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, i32> {
    let end = cursor.checked_add(4).ok_or(-22)?;
    let chunk = bytes.get(*cursor..end).ok_or(-22)?;
    *cursor = end;
    chunk.try_into().map(u32::from_le_bytes).map_err(|_| -22)
}
fn take_bytes<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8], i32> {
    let end = cursor.checked_add(len).ok_or(-22)?;
    let chunk = bytes.get(*cursor..end).ok_or(-22)?;
    *cursor = end;
    Ok(chunk)
}
fn take_mac(bytes: &[u8], cursor: &mut usize) -> Result<[u8; 6], i32> {
    let mut mac = [0u8; 6];
    mac.copy_from_slice(take_bytes(bytes, cursor, 6)?);
    Ok(mac)
}

/// Band id for a band's representative frequency. Must stay in sync with
/// the band mapping in `nl80211::wiphy_attrs`, which renders these bands.
fn band_id_for(freq_mhz: u32) -> Option<u32> {
    match freq_mhz {
        2400..=2500 => Some(0),
        4900..=5900 => Some(1),
        5901..=7200 => Some(3),
        _ => None,
    }
}

/// Decode `REGISTER_WIPHY` (little-endian, exact length):
///
/// ```text
/// ifindex u32 | mac[6] | modes u32 | hw_caps u8 | cipher_count u8 | band_count u8
/// | flags u8 | max_scan_ssids u8 | reserved u8 | max_scan_ie_len u16
/// cipher_count x cipher_suite u32
/// per band: freq_mhz u32 | channel_count u8 | reserved u8 | channel_count x channel u8
/// ```
///
/// `ifindex` is the module's own netdev (`narf_netif_register_with_context`
/// on this device); the wiphy takes its name. `modes` are the
/// `WirelessModes` bits (STATION=1, AP=2, MONITOR=4, P2P=8); `hw_caps` bits
/// are HT=1, VHT=2, HE=4, EHT=8; `flags` are the `FLAG_*` SME offloads.
/// Reserved bytes must be zero, lengths must match exactly, every cipher must
/// be a known suite, band frequencies must map to distinct wiphy bands, and
/// channel numbers must be 1..=233, unique within their band.
fn decode_register_wiphy(request: &[u8]) -> Result<RegisterWiphy, i32> {
    let mut cursor = 0;
    let ifindex = take_u32(request, &mut cursor)?;
    let mac = take_mac(request, &mut cursor)?;
    let modes_raw = take_u32(request, &mut cursor)?;
    let hw_caps = take_u8(request, &mut cursor)?;
    let cipher_count = take_u8(request, &mut cursor)? as usize;
    let band_count = take_u8(request, &mut cursor)? as usize;
    let flags = take_u8(request, &mut cursor)?;
    let max_scan_ssids = take_u8(request, &mut cursor)?;
    let reserved = take_u8(request, &mut cursor)?;
    let max_scan_ie_len = take_u16(request, &mut cursor)?;
    if ifindex == 0
        || reserved != 0
        || flags & !KNOWN_FLAGS != 0
        || max_scan_ssids > MAX_SCAN_SSIDS
        || max_scan_ie_len > MAX_SCAN_IE_LEN
        || cipher_count > MAX_CIPHERS
        || band_count == 0
        || band_count > MAX_BANDS
    {
        return Err(-22);
    }
    let modes = WirelessModes::from_bits(modes_raw).ok_or(-22)?;
    if modes.is_empty() || hw_caps & !0xF != 0 {
        return Err(-22);
    }
    let mut ciphers = Vec::with_capacity(cipher_count);
    for _ in 0..cipher_count {
        let cipher = take_u32(request, &mut cursor)?;
        if !KNOWN_CIPHERS.contains(&cipher) || ciphers.contains(&cipher) {
            return Err(-22);
        }
        ciphers.push(cipher);
    }
    let mut bands = Vec::with_capacity(band_count);
    let mut seen_bands = Vec::with_capacity(band_count);
    for _ in 0..band_count {
        let freq_mhz = take_u32(request, &mut cursor)?;
        let channel_count = take_u8(request, &mut cursor)? as usize;
        if take_u8(request, &mut cursor)? != 0
            || channel_count == 0
            || channel_count > MAX_CHANNELS_PER_BAND
        {
            return Err(-22);
        }
        let band_id = band_id_for(freq_mhz).ok_or(-22)?;
        if seen_bands.contains(&band_id) {
            return Err(-22);
        }
        seen_bands.push(band_id);
        let mut channels = Vec::with_capacity(channel_count);
        for _ in 0..channel_count {
            let channel = take_u8(request, &mut cursor)? as u32;
            if channel == 0 || channel > MAX_CHANNEL_NUMBER || channels.contains(&channel) {
                return Err(-22);
            }
            channels.push(channel);
        }
        bands.push(WirelessBand { freq_mhz, channels });
    }
    if cursor != request.len() {
        return Err(-22);
    }
    Ok(RegisterWiphy {
        ifindex,
        mac,
        bands,
        modes,
        hw_caps: HwCaps {
            ht_supported: hw_caps & 1 != 0,
            vht_supported: hw_caps & 2 != 0,
            he_supported: hw_caps & 4 != 0,
            eht_supported: hw_caps & 8 != 0,
        },
        flags,
        max_scan_ssids,
        max_scan_ie_len,
        ciphers,
    })
}

fn security_from_wire(value: u8) -> Result<BssSecurity, i32> {
    Ok(match value {
        0 => BssSecurity::Open,
        1 => BssSecurity::Wep,
        2 => BssSecurity::Wpa,
        3 => BssSecurity::Wpa2,
        4 => BssSecurity::Wpa3,
        _ => return Err(-22),
    })
}

/// Decode `SCAN_RESULT` (little-endian, exact length):
///
/// ```text
/// bssid[6] | channel u8 | security u8 | frequency_mhz u32 | rssi i8 | reserved u8
/// | ssid_len u8 | reserved u8 | ie_len u16 | ssid | ies
/// ```
///
/// `security` is open/WEP/WPA/WPA2/WPA3 = 0..=4, `ssid_len` ≤ 32, `ie_len` ≤
/// 2048 (the beacon/probe-response body after the fixed fields).
fn decode_scan_result(request: &[u8]) -> Result<Bss, i32> {
    let mut cursor = 0;
    let bssid = take_mac(request, &mut cursor)?;
    let channel = u32::from(take_u8(request, &mut cursor)?);
    let security = security_from_wire(take_u8(request, &mut cursor)?)?;
    let frequency_mhz = take_u32(request, &mut cursor)?;
    let rssi = take_u8(request, &mut cursor)? as i8;
    let reserved_a = take_u8(request, &mut cursor)?;
    let ssid_len = take_u8(request, &mut cursor)? as usize;
    let reserved_b = take_u8(request, &mut cursor)?;
    let ie_len = take_u16(request, &mut cursor)? as usize;
    if reserved_a != 0
        || reserved_b != 0
        || ssid_len > MAX_SSID
        || ie_len > MAX_BSS_IES
        || band_id_for(frequency_mhz).is_none()
    {
        return Err(-22);
    }
    let ssid = take_bytes(request, &mut cursor, ssid_len)?.to_vec();
    let ies = take_bytes(request, &mut cursor, ie_len)?.to_vec();
    if cursor != request.len() {
        return Err(-22);
    }
    Ok(Bss {
        info: BssInfo {
            bssid,
            ssid,
            frequency_mhz,
            channel,
            rssi,
            security,
        },
        ies,
    })
}

/// Decode `CONNECT_RESULT`: `status u16 | reserved u16 | bssid[6] | reserved
/// u16 | frequency_mhz u32`. `status` is the IEEE 802.11 status code; 0 is
/// success and carries the associated BSS.
fn decode_connect_result(request: &[u8]) -> Result<(u16, [u8; 6], u32), i32> {
    let mut cursor = 0;
    let status = take_u16(request, &mut cursor)?;
    let reserved_a = take_u16(request, &mut cursor)?;
    let bssid = take_mac(request, &mut cursor)?;
    let reserved_b = take_u16(request, &mut cursor)?;
    let frequency_mhz = take_u32(request, &mut cursor)?;
    if reserved_a != 0 || reserved_b != 0 || cursor != request.len() {
        return Err(-22);
    }
    if status == 0 && (bssid == [0; 6] || band_id_for(frequency_mhz).is_none()) {
        return Err(-22);
    }
    Ok((status, bssid, frequency_mhz))
}

/// Decode `DISCONNECTED`: `reason u16 | locally_generated u8 | reserved u8`.
fn decode_disconnected(request: &[u8]) -> Result<(u16, bool), i32> {
    let mut cursor = 0;
    let reason = take_u16(request, &mut cursor)?;
    let local = take_u8(request, &mut cursor)?;
    let reserved = take_u8(request, &mut cursor)?;
    if local > 1 || reserved != 0 || cursor != request.len() {
        return Err(-22);
    }
    Ok((reason, local == 1))
}

/// Decode `SCAN_DONE`: `status i32` — 0, or a negative errno.
fn decode_scan_done(request: &[u8]) -> Result<i32, i32> {
    let mut cursor = 0;
    let status = take_u32(request, &mut cursor)? as i32;
    if status > 0 || cursor != request.len() {
        return Err(-22);
    }
    Ok(status)
}

/// Encode `SCAN_REQUEST`:
///
/// ```text
/// flags u8 (bit0 active) | frequency_count u8 | ssid_count u8 | reserved u8
/// | ie_len u16 | reserved u16 | frequencies u32[] | ssids (len u8 + bytes)[] | ies
/// ```
///
/// Frequencies are centre frequencies in MHz (empty = every channel the
/// wiphy advertised); an empty SSID list is a wildcard scan.
fn encode_scan_request(
    req: &ScanRequest,
    max_ssids: u8,
    max_ie_len: u16,
) -> Result<Vec<u8>, WirelessError> {
    if req.ssids.len() > usize::from(max_ssids.max(1))
        || req.ssids.iter().any(|s| s.len() > MAX_SSID)
        || req.frequencies_mhz.len() > 255
    {
        return Err(WirelessError::InvalidArgs);
    }
    // Legacy channel-only requests (no frequency) are 2.4/5 GHz numbers.
    let mut frequencies = req.frequencies_mhz.clone();
    if frequencies.is_empty() {
        for &channel in &req.channels {
            let freq = match channel {
                1..=13 => 2407 + 5 * channel,
                14 => 2484,
                32..=177 => 5000 + 5 * channel,
                _ => return Err(WirelessError::InvalidArgs),
            };
            frequencies.push(freq);
        }
    }
    if frequencies.len() > 255 || req.extra_ies.len() > usize::from(max_ie_len) {
        return Err(WirelessError::InvalidArgs);
    }
    let mut out = alloc::vec![
        u8::from(req.active),
        frequencies.len() as u8,
        req.ssids.len() as u8,
        0,
    ];
    out.extend_from_slice(&(req.extra_ies.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    for freq in frequencies {
        out.extend_from_slice(&freq.to_le_bytes());
    }
    for ssid in &req.ssids {
        out.push(ssid.len() as u8);
        out.extend_from_slice(ssid);
    }
    out.extend_from_slice(&req.extra_ies);
    Ok(out)
}

/// Encode `CONNECT`:
///
/// ```text
/// bssid[6] | security u8 | reserved u8 | frequency_mhz u32 | ssid_len u8
/// | reserved u8 | ie_len u16 | secret_len u16 | reserved u16 | ssid | ies | secret
/// ```
///
/// `bssid` all-zero and `frequency_mhz` 0 leave the choice of BSS to the
/// module. `security` is [`SECURITY_OPEN`] (no secret), [`SECURITY_PSK`]
/// (32-byte PMK) or [`SECURITY_SAE`] (the password); a mode the module did
/// not advertise as offloaded, or an external supplicant, is refused here.
fn encode_connect(req: &AssociateRequest, flags: u8) -> Result<Vec<u8>, WirelessError> {
    let (security, secret): (u8, &[u8]) = match &req.security {
        SecurityConfig::Open => (SECURITY_OPEN, &[]),
        SecurityConfig::Wpa2 { psk } if flags & FLAG_PSK_OFFLOAD != 0 => (SECURITY_PSK, psk),
        SecurityConfig::Wpa3 { password }
            if flags & FLAG_SAE_OFFLOAD != 0
                && !password.is_empty()
                && password.len() <= MAX_SAE_PASSWORD =>
        {
            (SECURITY_SAE, password)
        }
        _ => return Err(WirelessError::NotSupported),
    };
    if req.ssid.is_empty() || req.ssid.len() > MAX_SSID || req.ie.len() > MAX_BSS_IES {
        return Err(WirelessError::InvalidArgs);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&req.bssid);
    out.push(security);
    out.push(0);
    out.extend_from_slice(&req.frequency_mhz.to_le_bytes());
    out.push(req.ssid.len() as u8);
    out.push(0);
    out.extend_from_slice(&(req.ie.len() as u16).to_le_bytes());
    out.extend_from_slice(&(secret.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&req.ssid);
    out.extend_from_slice(&req.ie);
    out.extend_from_slice(secret);
    Ok(out)
}

/// Encode `DISCONNECT`: `reason u16 | reserved u16`.
fn encode_disconnect(reason: u16) -> [u8; 4] {
    let mut out = [0u8; 4];
    out[..2].copy_from_slice(&reason.to_le_bytes());
    out
}

/// Malformed/unsupported requests cause no allocation, native I/O, queue
/// mutation or operation-id publication.
fn validate(opcode: u32, request: &[u8]) -> Result<(), i32> {
    match opcode {
        OP_REGISTER_WIPHY => decode_register_wiphy(request).map(|_| ()),
        OP_SCAN_RESULT => decode_scan_result(request).map(|_| ()),
        OP_SCAN_DONE => decode_scan_done(request).map(|_| ()),
        OP_CONNECT_RESULT => decode_connect_result(request).map(|_| ()),
        OP_DISCONNECTED => decode_disconnected(request).map(|_| ()),
        _ => Err(-95),
    }
}

/// Mint a stable wiphy id.
fn alloc_wiphy_id() -> Result<u64, i32> {
    let counter = NEXT_WIPHY
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |id| id.checked_add(1))
        .map_err(|_| -75)?;
    Ok(MODULE_WIPHY_ID_BASE | counter)
}

fn execute(session: &Arc<Session>, opcode: u32, request: &[u8]) -> Result<Vec<u8>, i32> {
    if opcode == OP_REGISTER_WIPHY {
        return register_wiphy(session, request);
    }
    // Every report needs the wiphy it reports on.
    let shell = session.wiphy.lock().clone().ok_or(-22)?;
    match opcode {
        OP_SCAN_RESULT => shell.report_scan_result(decode_scan_result(request)?)?,
        OP_SCAN_DONE => shell.report_scan_done(decode_scan_done(request)?),
        OP_CONNECT_RESULT => {
            let (status, bssid, _frequency) = decode_connect_result(request)?;
            shell.report_connect(status, bssid);
        }
        OP_DISCONNECTED => {
            let (reason, local) = decode_disconnected(request)?;
            shell.report_disconnect(reason, local);
        }
        _ => return Err(-95),
    }
    Ok(Vec::new())
}

fn register_wiphy(session: &Arc<Session>, request: &[u8]) -> Result<Vec<u8>, i32> {
    if session.wiphy.lock().is_some() {
        return Err(-16);
    }
    let decoded = decode_register_wiphy(request)?;
    // The wiphy is the module's netdev's: registered by this very module on
    // this very device, with this ifindex.
    let name = narf_bus::driver_match::module_netif_name(session.owner, session.token, decoded.ifindex)
        .ok_or(-19)?;
    let _guard = REGISTER_GUARD.lock();
    if session.wiphy.lock().is_some() {
        return Err(-16);
    }
    if registry::list().iter().any(|iface| iface.name() == name) {
        return Err(-17);
    }
    let wiphy_id = alloc_wiphy_id()?;
    let ciphers: &'static [u32] = Box::leak(decoded.ciphers.into_boxed_slice());
    let shell = Arc::new(ModuleWiphy {
        name: name.clone(),
        mac: decoded.mac,
        wiphy_id,
        session_id: session.id,
        flags: decoded.flags,
        max_scan_ssids: decoded.max_scan_ssids,
        max_scan_ie_len: decoded.max_scan_ie_len,
        info: IrqSafeSpinLock::new(WirelessIfaceInfo {
            base_name: name,
            base_mac: decoded.mac,
            bands: decoded.bands,
            modes: decoded.modes,
            hw_caps: decoded.hw_caps,
        }),
        ciphers,
        connected: AtomicBool::new(false),
        state: IrqSafeSpinLock::new(ShellState {
            bssid: None,
            scan: None,
            bss: Vec::new(),
            pending: Pending::Idle,
        }),
        rx: IrqSafeSpinLock::new(None),
        tx: IrqSafeSpinLock::new(None),
    });
    registry::register(shell.clone());
    let index = registry::wiphy_index(wiphy_id).ok_or(-5)?;
    *session.wiphy.lock() = Some(shell);
    Ok(index.to_le_bytes().to_vec())
}

fn open(
    owner: u64,
    token: u64,
    id: u64,
    _device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    event: Option<ModuleWirelessEventFn>,
) -> Result<(), i32> {
    // No device I/O here: the broker already proved this session is bound
    // to the module's exact probe device. The module owns the chip; the
    // host owns the wiphy record.
    cap.invoke(Current).map_err(|_| -19)?;
    insert_session(new_session(id, owner, token, cap, event))
}

/// Build a session. The probe device itself is not stored: the broker
/// already proved the binding, and every host action keys off the session.
fn new_session(
    id: u64,
    owner: u64,
    token: u64,
    cap: Cap<BusDeviceCap, Write>,
    event: Option<ModuleWirelessEventFn>,
) -> Arc<Session> {
    Arc::new(Session {
        id,
        owner,
        token,
        cap,
        closed: AtomicBool::new(false),
        event,
        operation: Mutex::new(None),
        wiphy: IrqSafeSpinLock::new(None),
    })
}

/// Publish a session. One session per probe device: this host serves every
/// Wi-Fi device on the machine, so the check is per (owner, token).
fn insert_session(entry: Arc<Session>) -> Result<(), i32> {
    let mut sessions = SESSIONS.lock();
    if sessions
        .iter()
        .any(|s| s.owner == entry.owner && s.token == entry.token)
    {
        return Err(-16);
    }
    sessions.push(entry);
    Ok(())
}

fn submit(id: u64, opcode: u32, request: &[u8]) -> Result<u64, i32> {
    validate(opcode, request)?;
    let session = session(id)?;
    session.current()?;
    let mut slot = session.operation.try_lock().ok_or(-16)?;
    if slot.is_some() {
        return Err(-16);
    }
    let operation = NEXT_OPERATION
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |id| id.checked_add(1))
        .map_err(|_| -75)?;
    let result = execute(&session, opcode, request);
    *slot = Some(Operation {
        id: operation,
        started: true,
        cancelled: false,
        future: None,
        result: Some(result),
    });
    Ok(operation)
}

fn poll(
    id: u64,
    operation: u64,
    capacity: usize,
    publish: &mut narf_bus::module_wireless::Publish<'_>,
) -> (i32, usize) {
    let session = match session(id) {
        Ok(s) => s,
        Err(e) => return (e, 0),
    };
    if let Err(error) = session.current() {
        return (error, 0);
    }
    let Some(mut slot) = session.operation.try_lock() else {
        return (-11, 0);
    };
    let Some(work) = slot.as_mut().filter(|work| work.id == operation) else {
        return (-22, 0);
    };
    work.advance(&mut Context::from_waker(Waker::noop()));
    if session.current().is_err() {
        return (-19, 0);
    }
    let Some(result) = work.result.as_ref() else {
        return (-11, 0);
    };
    let result = match result {
        Err(error) => (*error, 0),
        Ok(bytes) => {
            if capacity < bytes.len() {
                return (-105, bytes.len());
            }
            match publish(bytes) {
                Ok(()) => (0, bytes.len()),
                Err(error) => (error, 0),
            }
        }
    };
    *slot = None;
    result
}

fn cancel(id: u64, operation: u64) -> i32 {
    let session = match session(id) {
        Ok(s) => s,
        Err(e) => return e,
    };
    if let Err(error) = session.current() {
        return error;
    }
    let Some(mut slot) = session.operation.try_lock() else {
        return -16;
    };
    let Some(work) = slot.as_mut().filter(|work| work.id == operation) else {
        return -22;
    };
    work.request_cancel();
    0
}

fn close(id: u64) {
    let removed = {
        let mut sessions = SESSIONS.lock();
        sessions
            .iter()
            .position(|s| s.id == id)
            .map(|index| sessions.remove(index))
    };
    let Some(session) = removed else {
        return;
    };
    session.closed.store(true, Ordering::Release);
    if let Some(wiphy) = session.wiphy.lock().take() {
        // The radio is going away: an association does not survive it.
        if wiphy.state.lock().bssid.take().is_some() {
            crate::nl80211::notify_disconnect(&wiphy.name, 3, false);
        }
        wiphy.set_carrier(false);
        crate::nl80211::notify_interface_removed(wiphy.as_ref());
        registry::unregister(wiphy.name());
    }
    session.cap.revoke();
    narf_scheduler::spawn(async move {
        let mut slot = session.operation.lock().await;
        if let Some(work) = slot.as_mut() {
            if work.started {
                if let Some(future) = work.future.take() {
                    let _ = future.await;
                }
            }
        }
        *slot = None;
    });
}
