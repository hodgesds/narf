//! Native wireless family host (family `WIFI`, version 1).
//!
//! The first `module_wireless::Host`: the cfg80211 glue that makes Wi-Fi
//! `.ko` datapaths work. A loadable frontend owns its probe device and chip;
//! the native side owns only the 802.11 control plane (the wiphy record)
//! and the per-session event channel. This mirrors e1000 (module runs the
//! datapath, native provides the netdev/control plane) and the mt76
//! copy-mode host, but the protocol here is the generic family protocol
//! from `drivers/wireless/specification/rtw88-usb-module-datapath.md`,
//! not a per-family private one.
//!
//! Stage 3 scope (this file): the host skeleton, `open` / `submit` /
//! `poll` / `cancel` / `close` dispatch, the `REGISTER_WIPHY` opcode path
//! (bands/channels/cipher caps → assigned wiphy index), and the
//! session/event-callback plumbing for the per-session event callback ABI
//! addition (`narf_wireless_open_with_event`). The full scan/connect/key
//! opcode set is Stage 4: the operation table below already carries the
//! async-future shape Stage 4 plugs into (same as the mt76 host — a boxed
//! future advanced with a noop waker on each poll), and the shell's
//! `scan` / `associate` / `disassociate` / `set_config` return
//! `NotSupported` until Stage 4 emits the corresponding event through
//! [`deliver_event`] and correlates the module's result.
//!
//! Lifetime rules (same contract as every `module_wireless::Host`):
//! hosts are kernel-resident — no hook points into unloadable text. The
//! module's event callback is the one exception, and it is stored in the
//! session, invoked only through the bus call gate (which pins the live
//! module and enters its effective domain), and forgotten when the session
//! closes or the device is retired. `cancel` / `close` never free
//! hardware-owned memory; started native work reaches its terminal result
//! past `close` in a spawned task. Requests and replies are bounded copies
//! (`MAX_REQUEST` / `MAX_REPLY`); no Rust object, firmware pointer, DMA
//! pointer or future crosses the boundary.
//!
//! Perf class: no hot path. The host runs at bring-up and at
//! scan/connect/key rates; TX/RX frames never pass through it (they flow
//! through the module's netdev via `narf_netif_rx` / `tx_callback`).

use crate::{
    iface::{HwCaps, WirelessBand, WirelessIfaceInfo, WirelessModes},
    registry,
    scan::{BssInfo, ScanRequest},
    AssociateRequest, WirelessConfig, WirelessError, WirelessNetIface,
};
use alloc::{boxed::Box, format, string::String, sync::Arc, vec::Vec};
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
/// repurposing an opcode.
pub const VERSION: u32 = 1;

/// Module → native control-plane opcodes (family `WIFI`, version 1).
pub const OP_REGISTER_WIPHY: u32 = 0x01;
/// Stage 4: one scan result (BSS) fed to the native stack.
pub const OP_SCAN_RESULT: u32 = 0x02;
/// Stage 4: connect/auth outcome report.
pub const OP_CONNECT_RESULT: u32 = 0x03;
/// Stage 4: link-loss report.
pub const OP_DISCONNECT: u32 = 0x04;
/// Stage 4: op-state mirror (parked/awake) for the chip stage machine.
pub const OP_SET_STATE: u32 = 0x05;

/// Native → module control-plane events, delivered through the per-session
/// event callback registered by `narf_wireless_open_with_event`. This is a
/// separate namespace from the submit opcodes above: an event id is never
/// a valid submit opcode and vice versa. Payload layouts are defined per
/// event when Stage 4 wires the corresponding shell operation.
pub const EVENT_SCAN_REQUEST: u32 = 0x01;
pub const EVENT_CONNECT: u32 = 0x02;
pub const EVENT_KEY: u32 = 0x03;
pub const EVENT_TX_FRAME: u32 = 0x04;

/// `REGISTER_WIPHY` wire limits. The whole request stays far under
/// `MAX_REQUEST` (4096): at most 14 + 4*8 + 3*(6+64) = 256 bytes.
const MAX_CIPHERS: usize = 8;
const MAX_BANDS: usize = 3;
const MAX_CHANNELS_PER_BAND: usize = 64;
const MAX_CHANNEL_NUMBER: u32 = 233;

/// Stable wiphy ids minted by this host live in this range so they can
/// never collide with the builtin drivers' FNV-1a(name) ids, and never
/// overlap the control-wdev space (bit 63). The low bits are the host's
/// registration counter.
const MODULE_WIPHY_ID_BASE: u64 = 1 << 62;

static SESSIONS: IrqSafeSpinLock<Vec<Arc<Session>>> = IrqSafeSpinLock::new(Vec::new());
static NEXT_OPERATION: AtomicU64 = AtomicU64::new(1);
static NEXT_WIPHY: AtomicU64 = AtomicU64::new(0);
/// Serialises wiphy registration (name check + `registry::register`) so
/// two concurrent `REGISTER_WIPHY` submissions can never publish the same
/// shell name. Registration is bring-up-only work; the guard is never held
/// across a poll or an event delivery.
static REGISTER_GUARD: IrqSafeSpinLock<()> = IrqSafeSpinLock::new(());

/// Cipher suites a module may advertise. Anything else is rejected at the
/// boundary: the host must never advertise a suite its key path cannot
/// honour, and Stage 4 key ops install/remove keys against exactly this set.
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
/// Idempotent for the same host; a different host for this family is
/// refused by the broker (`-EBUSY`) and ignored here, like the mt76 host.
pub fn register() {
    let _ = narf_bus::module_wireless::register(&HOST);
}

/// Deliver one native→module control-plane event to a session's callback.
/// Stage 4 calls this from the wiphy shell (`scan` emits
/// `EVENT_SCAN_REQUEST`, and so on). Returns `-EOPNOTSUPP` for an unknown
/// event, `-EINVAL` for an over-bounded payload, and `-ENODEV` when the
/// session is unknown, closed, revoked, or was opened without an event
/// callback (plain `narf_wireless_open` sessions have no event channel).
/// A successful return is the callback's own return: the module reports
/// whether it accepted the event.
pub fn deliver_event(session_id: u64, event: u32, payload: &[u8]) -> i32 {
    if !matches!(
        event,
        EVENT_SCAN_REQUEST | EVENT_CONNECT | EVENT_KEY | EVENT_TX_FRAME
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

/// Native work behind one submitted operation. Same shape as the mt76 host:
/// a boxed future advanced with a noop waker on each poll (the module's
/// periodic poller drives progress), so Stage 4 async work (scan/connect)
/// plugs into this slot without reshaping the host. `REGISTER_WIPHY`
/// completes synchronously at submit: `future` is `None` and `result` is
/// already set.
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

/// Native wiphy shell for one module session.
///
/// The shell is the cfg80211-visible side of the module's radio: it carries
/// the bands/channels/modes/caps the module advertised at `REGISTER_WIPHY`
/// into `get_wireless_info` (which nl80211 renders as the wiphy bands) and
/// the cipher suites into `cipher_suites`. It is registered in
/// [`registry`] only — never in the net iface registry — because the
/// module's netdev is a separate object the module registers itself via
/// `narf_netif_register_with_context`; frames therefore never flow through
/// this shell, so its RX/TX rings stay `None` (nothing pumps them) and its
/// control operations return `NotSupported` until Stage 4 wires them to
/// [`deliver_event`].
///
/// Stage 4 finds the session for a shell operation by reverse lookup
/// (the session holding this shell's `Arc`), so no session back-pointer
/// is stored here.
pub struct ModuleWiphy {
    name: String,
    mac: [u8; 6],
    wiphy_id: u64,
    info: IrqSafeSpinLock<WirelessIfaceInfo>,
    /// Validated cipher suites, leaked once at registration so
    /// `cipher_suites()` can return the `&'static [u32]` the trait
    /// requires. One slice per session (a session registers at most one
    /// wiphy), bounded by the probe-device count; the bytes stay valid for
    /// the process lifetime, so unregistering the wiphy cannot invalidate
    /// an outstanding `&'static` borrow.
    ciphers: &'static [u32],
    /// Association state. Always false in Stage 3; Stage 4 sets it on the
    /// module's `CONNECT_RESULT` / `DISCONNECT` reports.
    connected: AtomicBool,
    rx: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
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

#[async_trait]
impl WirelessNetIface for ModuleWiphy {
    /// The stable id minted at `REGISTER_WIPHY`, not the default
    /// FNV-1a(name): the registry keys the wiphy index off this value, so
    /// the reply index and every later `wiphy_index` lookup agree.
    fn wiphy_id(&self) -> u64 {
        self.wiphy_id
    }
    fn get_wireless_info(&self) -> WirelessIfaceInfo {
        self.info.lock().clone()
    }
    fn cipher_suites(&self) -> &'static [u32] {
        self.ciphers
    }
    async fn scan(&self, _req: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        // Stage 4: emit EVENT_SCAN_REQUEST through the session callback and
        // await the module's SCAN_RESULT. No scan path exists yet.
        Err(WirelessError::NotSupported)
    }
    async fn associate(&self, _req: AssociateRequest) -> Result<(), WirelessError> {
        // Stage 4: EVENT_CONNECT + CONNECT_RESULT correlation.
        Err(WirelessError::NotSupported)
    }
    async fn disassociate(&self) -> Result<(), WirelessError> {
        // Stage 4: driven by the module's DISCONNECT report.
        Err(WirelessError::NotSupported)
    }
    async fn set_config(&self, _cfg: WirelessConfig) -> Result<(), WirelessError> {
        // Stage 4: channel/power requests reach the module as events.
        Err(WirelessError::NotSupported)
    }
}

/// Decoded `REGISTER_WIPHY` request: the wiphy advertisement plus the
/// validated cipher suites the module's key path can honour.
#[derive(Debug, PartialEq, Eq)]
struct RegisterWiphy {
    mac: [u8; 6],
    bands: Vec<WirelessBand>,
    modes: WirelessModes,
    hw_caps: HwCaps,
    ciphers: Vec<u32>,
}

fn take_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, i32> {
    let byte = bytes.get(*cursor).ok_or(-22)?;
    *cursor += 1;
    Ok(*byte)
}
fn take_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, i32> {
    let end = cursor.checked_add(4).ok_or(-22)?;
    let chunk = bytes.get(*cursor..end).ok_or(-22)?;
    *cursor = end;
    chunk.try_into().map(u32::from_le_bytes).map_err(|_| -22)
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
/// mac[6] | modes u32 | hw_caps u8 | cipher_count u8 | band_count u8 | reserved u8
/// cipher_count x cipher_suite u32
/// per band: freq_mhz u32 | channel_count u8 | reserved u8 | channel_count x channel u8
/// ```
///
/// `modes` are the `WirelessModes` bits (STATION=1, AP=2, MONITOR=4,
/// P2P=8); `hw_caps` bits are HT=1, VHT=2, HE=4, EHT=8. Reserved bytes
/// must be zero, lengths must match exactly, every cipher must be a known
/// suite, every band frequency must map to a wiphy band, bands must not
/// repeat, and channel numbers must be 1..=233, unique within their band.
fn decode_register_wiphy(request: &[u8]) -> Result<RegisterWiphy, i32> {
    if request.len() < 14 {
        return Err(-22);
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&request[..6]);
    let mut cursor = 6;
    let modes_raw = take_u32(request, &mut cursor)?;
    let hw_caps = take_u8(request, &mut cursor)?;
    let cipher_count = take_u8(request, &mut cursor)? as usize;
    let band_count = take_u8(request, &mut cursor)? as usize;
    if take_u8(request, &mut cursor)? != 0 {
        return Err(-22);
    }
    if cipher_count > MAX_CIPHERS || band_count == 0 || band_count > MAX_BANDS {
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
        mac,
        bands,
        modes,
        hw_caps: HwCaps {
            ht_supported: hw_caps & 1 != 0,
            vht_supported: hw_caps & 2 != 0,
            he_supported: hw_caps & 4 != 0,
            eht_supported: hw_caps & 8 != 0,
        },
        ciphers,
    })
}

/// Reply to `REGISTER_WIPHY`: the assigned wiphy index, little-endian.
fn encode_register_wiphy_reply(wiphy_index: u32) -> Vec<u8> {
    wiphy_index.to_le_bytes().to_vec()
}

/// Malformed/unsupported requests cause no future allocation, native I/O,
/// queue mutation or operation-id publication. Stage 4 opcodes are
/// recognised but report `-EOPNOTSUPP` until their execution lands.
fn validate(opcode: u32, request: &[u8]) -> Result<(), i32> {
    match opcode {
        OP_REGISTER_WIPHY => decode_register_wiphy(request).map(|_| ()),
        OP_SCAN_RESULT | OP_CONNECT_RESULT | OP_DISCONNECT | OP_SET_STATE => Err(-95),
        _ => Err(-95),
    }
}

/// Mint the shell identity: a stable wiphy id plus a name no registered
/// wiphy or netdev already holds, so nl80211 never resolves this shell to
/// another interface's ifindex. The registration guard serialises the
/// check-and-register pair; callers hold it across `registry::register`.
fn alloc_shell_identity() -> Result<(u64, String), i32> {
    loop {
        let counter = NEXT_WIPHY
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |id| id.checked_add(1))
            .map_err(|_| -75)?;
        let name = format!("wlan{counter}");
        let taken = registry::list().iter().any(|iface| iface.name() == name)
            || narf_net::iface::lookup(&name).is_some();
        if !taken {
            return Ok((MODULE_WIPHY_ID_BASE | counter, name));
        }
    }
}

fn execute(session: &Arc<Session>, opcode: u32, request: &[u8]) -> Result<Vec<u8>, i32> {
    match opcode {
        OP_REGISTER_WIPHY => {
            if session.wiphy.lock().is_some() {
                return Err(-16);
            }
            let decoded = decode_register_wiphy(request)?;
            // Serialise check-and-register: a second concurrent
            // REGISTER_WIPHY for this session must see the first shell.
            let _guard = REGISTER_GUARD.lock();
            if session.wiphy.lock().is_some() {
                return Err(-16);
            }
            let (wiphy_id, name) = alloc_shell_identity()?;
            let ciphers: &'static [u32] = Box::leak(decoded.ciphers.into_boxed_slice());
            let shell = Arc::new(ModuleWiphy {
                name: name.clone(),
                mac: decoded.mac,
                wiphy_id,
                info: IrqSafeSpinLock::new(WirelessIfaceInfo {
                    base_name: name,
                    base_mac: decoded.mac,
                    bands: decoded.bands,
                    modes: decoded.modes,
                    hw_caps: decoded.hw_caps,
                }),
                ciphers,
                connected: AtomicBool::new(false),
                rx: IrqSafeSpinLock::new(None),
                tx: IrqSafeSpinLock::new(None),
            });
            registry::register(shell.clone());
            let index = registry::wiphy_index(wiphy_id).ok_or(-5)?;
            *session.wiphy.lock() = Some(shell);
            Ok(encode_register_wiphy_reply(index))
        }
        _ => Err(-95),
    }
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
    // to the module's exact probe device, and the wiphy shell is minted by
    // REGISTER_WIPHY, not by opening. The host performs no device I/O at
    // all — the module owns the chip; the host owns the wiphy record.
    cap.invoke(Current).map_err(|_| -19)?;
    insert_session(new_session(id, owner, token, cap, event))
}

/// Build a session. The probe device itself is not stored: the broker
/// already proved the binding, and every host action keys off the session,
/// not the device.
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

/// Publish a session. One session per probe device: unlike the mt76
/// single-session host, this host serves every Wi-Fi device on the machine,
/// so the check is per (owner, token), not global.
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
    // Malformed/unsupported requests cause no future allocation, native I/O,
    // queue mutation or operation-id publication.
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
    // Stage 3 opcodes execute synchronously; Stage 4 will store a future
    // here instead and let `poll` advance it.
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
    // The module's periodic poller drives progress even when a future's
    // IRQ/timer waker fires between these calls.
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
    // Started native work is never dropped. It reaches its actual terminal
    // result; successful effects are reported EALREADY, never fake Cancelled.
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
        registry::unregister(wiphy.name());
    }
    // Stop every subsequent native invocation. Uncertain native work
    // remains retained rather than being freed on revocation.
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
