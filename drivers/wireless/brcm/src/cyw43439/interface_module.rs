// SPDX-License-Identifier: GPL-2.0-or-later
//! The module build's netdev (`brcmfmac.ko`): the FullMAC station behind the
//! KABI.
//!
//! Built in, [`super::interface`] is the full shell: AP, monitor, P2P and
//! virtual interfaces, WoWL and system PM, the host-supplicant control port,
//! roaming, power save and the generation swap on firmware reset. A module
//! reaches the network stack only through the netif bridge and the `WIFI`
//! family host (`wireless/src/module_host.rs`, version 2), so this is the
//! station subset over the same [`Station`] the built-in shell drives, call
//! for call:
//!
//! - **netdev** — `narf_netif_register_with_context` (the bridge names it
//!   `wlan%d` because the device has a wireless session); TX frames arrive
//!   in [`tx_callback`], RX goes out through `narf_netif_rx`;
//! - **wiphy** — `REGISTER_WIPHY` advertises the station's regulatory-
//!   admitted channels, HT/VHT, the ciphers the built-in shell reports and
//!   the firmware SME: brcmfmac is FullMAC, so the firmware runs
//!   authentication and association, and with `sup_wpa` its own supplicant
//!   runs the 4-way handshake from the PMK (`PSK_OFFLOAD`), with SAE in
//!   firmware where `cap` lists `sae` (`SAE_OFFLOAD`);
//! - **control** — the host's `SCAN_REQUEST` / `CONNECT` / `DISCONNECT`
//!   events run [`Station::scan`] / [`Station::associate`] /
//!   [`Station::disconnect`], whose outcomes go back as `SCAN_RESULT` /
//!   `SCAN_DONE` / `CONNECT_RESULT` / `DISCONNECTED`;
//! - **link** — carrier follows those reports; a link loss the station's
//!   event poll observes is reported as `DISCONNECTED`.
//!
//! - **recovery** — a terminal transport (firmware halt, fatal protocol or
//!   access error) is reset in place as the built-in `Generation::recover`
//!   does it (Linux `brcmf_fw_crashed` -> `brcmf_pcie_reset`): carrier off,
//!   the confirmed stop, the device reset and a fresh signed download, a
//!   re-initialized station on the same netdev, then a rejoin of the
//!   retained association. At most [`MAX_RESETS`] times.
//!
//! Not carried (built-in only): AP, monitor, P2P and virtual interfaces,
//! WoWL and system PM, power-save control, the host supplicant
//! (`SecurityConfig::External`) and nl80211 PMKSA entries (the v2 host
//! carries none: the firmware list is kept empty, as built in without any).

use alloc::{collections::VecDeque, string::String, sync::Arc, vec::Vec};
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use narf_wireless::scan::BssSecurity;
use narf_wireless::{AssociateRequest, BssInfo, ScanRequest, SecurityConfig};

use super::fullmac::Fullmac;
use super::runtime::Error;
use super::station::{PolicySource, Station};
use crate::brcmfmac::{pcie_kabi::KabiBackplane, station_transport::Adapter};
use crate::platform::{self, Console, IrqSafeSpinLock, Mutex};

/// The PCIe station transport of the module.
pub type ModuleAdapter = Adapter<KabiBackplane>;
/// The module's FullMAC station.
pub type ModuleStation = Station<ModuleAdapter>;

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
    pub const FLAG_SAE_OFFLOAD: u8 = 0x02;
    pub const FLAG_REPORTS_DISCONNECT: u8 = 0x04;
    pub const SECURITY_OPEN: u8 = 0;
    pub const SECURITY_PSK: u8 = 1;
    pub const SECURITY_SAE: u8 = 2;
    /// IEEE 802.11 status: unspecified failure.
    pub const STATUS_UNSPECIFIED_FAILURE: u16 = 1;
    /// IEEE 802.11 reasons: unspecified; deauthenticated, leaving.
    pub const REASON_UNSPECIFIED: u16 = 1;
    pub const REASON_DEAUTH_LEAVING: u16 = 3;
}

/// Frames queued between the stack and the service loop.
const TX_QUEUE_MAX: usize = 512;
/// Frames moved per direction per service step (the built-in drain).
const STEP_BUDGET: usize = 32;
const ENODEV: i32 = -19;
const EINVAL: i32 = -22;
const ENOBUFS: i32 = -105;
const EOPNOTSUPP: i32 = -95;
/// Generations one function may reset through before it stays down
/// (`generation::MAX_RESETS`).
const MAX_RESETS: u32 = 64;

/// The last association's request, kept for the rejoin after a reset (the
/// built-in `lifecycle.request`).
#[derive(Clone)]
struct Retained {
    bssid: [u8; 6],
    ssid: Vec<u8>,
    frequency_mhz: u32,
    channel: u32,
    /// `None` = open; `Some(Ok(pmk))` = PSK; `Some(Err(password))` = SAE.
    secret: Option<Result<[u8; 32], Vec<u8>>>,
}
impl Retained {
    fn of(request: &AssociateRequest) -> Option<Self> {
        let secret = match &request.security {
            SecurityConfig::Open => None,
            SecurityConfig::Wpa2 { psk } => Some(Ok(*psk)),
            SecurityConfig::Wpa3 { password } => Some(Err(password.clone())),
            _ => return None,
        };
        Some(Self {
            bssid: request.bssid,
            ssid: request.ssid.clone(),
            frequency_mhz: request.frequency_mhz,
            channel: request.channel,
            secret,
        })
    }
    fn request(&self) -> AssociateRequest {
        AssociateRequest {
            bssid: self.bssid,
            ssid: self.ssid.clone(),
            frequency_mhz: self.frequency_mhz,
            channel: self.channel,
            security: match &self.secret {
                None => SecurityConfig::Open,
                Some(Ok(psk)) => SecurityConfig::Wpa2 { psk: *psk },
                Some(Err(password)) => SecurityConfig::Wpa3 {
                    password: password.clone(),
                },
            },
            ie: Vec::new(),
        }
    }
}

/// The fixed signed regulatory domain the module was provisioned under:
/// the built-in `GlobalPolicy` reads the kernel's live database, which a
/// module cannot reach, so the station keeps the snapshot it booted with
/// (a different country needs a reload, as the built-in requires a reset).
struct FixedPolicy(Arc<narf_wireless::reg::RegulatoryDomain>);
impl PolicySource for FixedPolicy {
    fn snapshot(&self) -> Option<Arc<narf_wireless::reg::RegulatoryDomain>> {
        Some(self.0.clone())
    }
}

/// The station netdev of the module build.
#[allow(missing_debug_implementations)]
pub struct ModuleNetdev {
    mac: [u8; 6],
    ifindex: u32,
    session: u64,
    station: Mutex<ModuleStation>,
    /// bit 63 = associated, low 48 bits = BSSID (LE).
    bssid: AtomicU64,
    /// Carrier as last reported to the host.
    up: AtomicBool,
    /// The transport is terminal and awaits the reset in the service loop.
    failed: AtomicBool,
    /// A reset failed (or the limit was reached): nothing is serviced.
    dead: AtomicBool,
    resets: AtomicU32,
    /// The signed domain every generation's station is initialized under.
    domain: Arc<narf_wireless::reg::RegulatoryDomain>,
    retained: IrqSafeSpinLock<Option<Retained>>,
    tx: IrqSafeSpinLock<VecDeque<Vec<u8>>>,
}

/// The one radio. Callbacks find it here.
static NETDEV: IrqSafeSpinLock<Option<Arc<ModuleNetdev>>> = IrqSafeSpinLock::new(None);

fn netdev() -> Option<Arc<ModuleNetdev>> {
    NETDEV.lock().clone()
}

fn log(args: core::fmt::Arguments<'_>) {
    let _ = writeln!(Console, "  brcmfmac.ko: {}", args);
}

fn pack(bssid: Option<[u8; 6]>) -> u64 {
    bssid.map_or(0, |b| {
        let mut packed = 1u64 << 63;
        for (i, byte) in b.iter().enumerate() {
            packed |= u64::from(*byte) << (8 * i);
        }
        packed
    })
}

/// Linux `brcmf_netdev_start_xmit` admission, as built in
/// (`interface.rs::transmit_admitted`): Ethernet II from this station,
/// never EAPOL (the firmware supplicant owns the port).
fn transmit_admitted(bytes: &[u8], local: [u8; 6]) -> bool {
    (14..=1514).contains(&bytes.len())
        && u16::from_be_bytes([bytes[12], bytes[13]]) >= 0x600
        && bytes[6..12] == local
        && bytes[12..14] != [0x88, 0x8e]
}

/// `interface.rs::receive_admitted`: Ethernet II to this station or a
/// group, from a unicast source, never EAPOL.
fn receive_admitted(bytes: &[u8], local: [u8; 6]) -> bool {
    (14..=1514).contains(&bytes.len())
        && u16::from_be_bytes([bytes[12], bytes[13]]) >= 0x600
        && bytes[12..14] != [0x88, 0x8e]
        && (bytes[0] & 1 != 0 || bytes[..6] == local)
        && bytes[6] & 1 == 0
        && bytes[6..12] != [0; 6]
}

fn freq_to_channel(mhz: u32) -> u32 {
    match mhz {
        2484 => 14,
        2412..=2472 => (mhz - 2407) / 5,
        5000..=5900 => (mhz - 5000) / 5,
        _ => 0,
    }
}

impl ModuleNetdev {
    fn connected(&self) -> Option<[u8; 6]> {
        let packed = self.bssid.load(Ordering::Acquire);
        (packed >> 63 == 1).then(|| {
            let mut b = [0u8; 6];
            for (i, byte) in b.iter_mut().enumerate() {
                *byte = (packed >> (8 * i)) as u8;
            }
            b
        })
    }

    /// Submit a report to the family host and collect its status (every v2
    /// report completes at submit).
    fn report(&self, opcode: u32, request: &[u8]) -> i32 {
        let mut op = 0u64;
        // SAFETY: `request` names `len` readable bytes; `op` is a live local.
        let rc = unsafe {
            ffi::narf_wireless_submit(
                platform::device(),
                self.session,
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
                self.session,
                op,
                reply.as_mut_ptr(),
                reply.len(),
                &mut len,
            )
        }
    }

    /// Carrier on with the association.
    fn link_up(&self, bssid: [u8; 6], frequency_mhz: u32) {
        self.bssid.store(pack(Some(bssid)), Ordering::Release);
        self.up.store(true, Ordering::Release);
        let _ = self.report(
            wifi::OP_CONNECT_RESULT,
            &encode_connect_result(0, bssid, frequency_mhz),
        );
    }

    /// Carrier off, reporting why when it was up.
    fn link_down(&self, reason: u16, local: bool) {
        self.bssid.store(0, Ordering::Release);
        if self.up.swap(false, Ordering::AcqRel) {
            self.tx.lock().clear();
            let _ = self.report(wifi::OP_DISCONNECTED, &encode_disconnected(reason, local));
        }
    }

    /// The transport is terminal (the built-in shell's `power_save = 2`):
    /// carrier off; the service loop resets it ([`Self::recover`]).
    fn fail(&self, what: &str, error: Error) {
        if !self.failed.swap(true, Ordering::AcqRel) {
            log(format_args!(
                "{what} failed ({error:?}); resetting the transport"
            ));
        }
        self.link_down(wifi::REASON_UNSPECIFIED, false);
    }

    /// The built-in `Generation::recover` with the netdev kept: stop the
    /// terminal generation behind its proof, reset the device and download
    /// the re-verified firmware, re-initialize the station on the fresh
    /// generation, then rediscover and rejoin the retained BSS. A failure
    /// leaves the radio down (mappings pinned when the stop is unproven).
    async fn recover(&self) -> Result<(), Error> {
        self.link_down(wifi::REASON_UNSPECIFIED, false);
        let retained = self.retained.lock().take();
        {
            let mut station = self.station.lock().await;
            station.bssid = None;
            let runtime = &mut station.runtime;
            if runtime.stop_transport().await.is_err() {
                runtime.release_transport();
                return Err(Error::Failed);
            }
            if self.resets.load(Ordering::Acquire) >= MAX_RESETS {
                runtime.release_transport();
                return Err(Error::Failed);
            }
            if let Err(error) = runtime.reset_transport().await {
                runtime.release_transport();
                return Err(error);
            }
            let fresh = runtime.take_generation().ok_or(Error::Failed)?;
            self.resets.fetch_add(1, Ordering::AcqRel);
            let rebuilt = ModuleStation::initialize_live(
                alloc::boxed::Box::new(fresh),
                &[],
                Arc::new(FixedPolicy(self.domain.clone())),
            )
            .await?;
            if rebuilt.mac != self.mac {
                // The netdev's address is fixed; a different OTP MAC is a
                // different function.
                return Err(Error::Malformed);
            }
            *station = rebuilt;
        }
        self.tx.lock().clear();
        self.failed.store(false, Ordering::Release);
        log(format_args!(
            "transport reset, generation {} up",
            self.resets.load(Ordering::Acquire)
        ));
        if let Some(retained) = retained {
            // The fresh firmware has no scan results: rediscover the exact
            // retained BSS on its channel, then join it again.
            let scan = ScanRequest {
                ssids: alloc::vec![retained.ssid.clone()],
                frequencies_mhz: alloc::vec![retained.frequency_mhz],
                channels: alloc::vec![retained.channel],
                active: false,
                random_mac: None,
                colocated_6ghz: false,
                duration_tu: None,
                duration_mandatory: false,
                extra_ies: Vec::new(),
            };
            let found = self
                .scan(scan)
                .await
                .is_ok_and(|bss| bss.iter().any(|(b, _)| b.bssid == retained.bssid));
            if found {
                let _ = self.associate(retained.request()).await;
            }
        }
        Ok(())
    }

    /// One scan through the station (the built-in shell's `scan`).
    async fn scan(&self, request: ScanRequest) -> Result<Vec<(BssInfo, Vec<u8>)>, Error> {
        if self.dead.load(Ordering::Acquire) || self.failed.load(Ordering::Acquire) {
            return Err(Error::Failed);
        }
        let mut station = self.station.lock().await;
        let results = station.scan(request).await?;
        Ok(results
            .into_iter()
            .map(|bss| {
                let ies = station
                    .cache
                    .iter()
                    .find(|b| b.info.bssid == bss.bssid)
                    .map(|b| b.ies.clone())
                    .unwrap_or_default();
                (bss, ies)
            })
            .collect())
    }

    /// A `CONNECT` that left the BSS to the driver (zero BSSID or
    /// frequency): the strongest network of the last scan with that SSID
    /// and a matching security class (`cfg80211_get_bss`).
    fn resolve(station: &ModuleStation, mut request: AssociateRequest) -> Option<AssociateRequest> {
        if request.bssid != [0; 6] && request.frequency_mhz != 0 {
            return Some(request);
        }
        let wanted = |s: BssSecurity| match request.security {
            SecurityConfig::Open => matches!(s, BssSecurity::Open),
            SecurityConfig::Wpa3 { .. } => matches!(s, BssSecurity::Wpa3),
            _ => matches!(s, BssSecurity::Wpa2 | BssSecurity::Wpa3),
        };
        let bss = station
            .cache
            .iter()
            .map(|b| &b.info)
            .filter(|b| {
                if request.bssid != [0; 6] {
                    b.bssid == request.bssid
                } else {
                    b.ssid == request.ssid && wanted(b.security)
                }
            })
            .max_by_key(|b| b.rssi)?;
        request.bssid = bss.bssid;
        request.frequency_mhz = bss.frequency_mhz;
        request.channel = bss.channel;
        Some(request)
    }

    /// Associate with the firmware SME (the built-in shell's `associate`):
    /// open, WPA2-PSK from the PMK, or WPA3-SAE from the password.
    async fn associate(&self, request: AssociateRequest) -> Result<([u8; 6], u32), Error> {
        if matches!(request.security, SecurityConfig::External(_)) {
            return Err(Error::Unsupported);
        }
        if self.dead.load(Ordering::Acquire) || self.failed.load(Ordering::Acquire) {
            return Err(Error::Failed);
        }
        let mut station = self.station.lock().await;
        if station.bssid.is_some() {
            return Err(Error::Busy);
        }
        let request = Self::resolve(&station, request).ok_or(Error::Malformed)?;
        let frequency = request.frequency_mhz;
        let retained = Retained::of(&request);
        self.tx.lock().clear();
        // Firmware inserts cached PMKIDs into its (re)association RSNE; the
        // list must be current before the join (the v2 host carries no
        // PMKSA entries, so the desired list is empty).
        station
            .sync_pmksa(&super::station::pmksa::Cache::default())
            .await?;
        station.associate(request).await?;
        station.check_connection_policy()?;
        let bssid = station.bssid.ok_or(Error::Failed)?;
        *self.retained.lock() = retained;
        self.link_up(bssid, frequency);
        Ok((bssid, frequency))
    }

    /// Disconnect (the built-in shell's `disassociate`).
    async fn disassociate(&self) -> Result<(), Error> {
        self.retained.lock().take();
        self.tx.lock().clear();
        let mut station = self.station.lock().await;
        let result = station.disconnect().await;
        drop(station);
        self.link_down(wifi::REASON_DEAUTH_LEAVING, true);
        result
    }

    /// One service step (the built-in `Device::step` + `State::progress`,
    /// station subset): consume firmware events and link state, move
    /// queued TX into the flow rings and deliver received frames.
    fn step(&self) {
        if self.failed.load(Ordering::Acquire) {
            return;
        }
        let Some(mut station) = self.station.try_lock() else {
            return;
        };
        if station.runtime.transport_failed() {
            drop(station);
            self.fail("transport", Error::Failed);
            return;
        }
        if let Err(error) = station.poll() {
            // A policy or channel-adoption refusal closes the link; only a
            // terminal transport needs the reset (the built-in supervisor
            // also acts on `transport_failed` alone).
            let terminal = station.runtime.transport_failed();
            drop(station);
            if terminal {
                self.fail("station poll", error);
            } else {
                self.link_down(wifi::REASON_UNSPECIFIED, false);
            }
            return;
        }
        let bssid = station.bssid;
        if bssid.is_none() {
            drop(station);
            if self.up.load(Ordering::Acquire) {
                // Firmware reported the peer gone (deauth/disassoc/link).
                self.link_down(wifi::REASON_UNSPECIFIED, false);
            }
            return;
        }
        if !self.up.load(Ordering::Acquire) {
            // An association still completing in its own task.
            return;
        }
        for _ in 0..STEP_BUDGET {
            let Some(frame) = self.tx.lock().pop_front() else {
                break;
            };
            if !transmit_admitted(&frame, station.mac) {
                continue;
            }
            let priority = narf_drivers_wireless_ath_core::eth::classify8021d(&frame);
            match station.send_data(&frame, priority) {
                Ok(()) => {}
                Err(Error::Busy) => {
                    self.tx.lock().push_front(frame);
                    break;
                }
                Err(error) => {
                    station.runtime.fail();
                    station.bssid = None;
                    drop(station);
                    self.fail("transmit", error);
                    return;
                }
            }
        }
        let mac = station.mac;
        let mut received = Vec::new();
        for _ in 0..STEP_BUDGET {
            let Some(bytes) = station.runtime.pop_data() else {
                break;
            };
            if receive_admitted(&bytes, mac) {
                received.push(bytes);
            }
        }
        drop(station);
        for mut frame in received {
            // SAFETY: `frame` names `len` bytes the call may rewrite.
            let _ = unsafe {
                ffi::narf_netif_rx(
                    platform::device(),
                    self.ifindex,
                    frame.as_mut_ptr(),
                    frame.len(),
                )
            };
        }
    }

    /// The service loop: one step per wake of the runtime's interrupt
    /// signal, or every millisecond without a delivered vector.
    async fn run(self: Arc<Self>) {
        loop {
            if self.dead.load(Ordering::Acquire) {
                return;
            }
            if self.failed.load(Ordering::Acquire) {
                if let Err(error) = self.recover().await {
                    log(format_args!(
                        "transport reset failed ({error:?}); the radio is down until reload"
                    ));
                    self.dead.store(true, Ordering::Release);
                    return;
                }
            }
            self.step();
            let wake = self
                .station
                .try_lock()
                .and_then(|station| station.runtime.wake_source());
            match wake {
                Some((signal, delivered)) => {
                    let seen = signal.count();
                    let fallback = crate::brcmfmac::irq::fallback_ms(delivered);
                    let sleep = platform::time::sleep_cycles(platform::time::wall::ns_to_cycles(
                        fallback * 1_000_000,
                    ));
                    signal.wait(seen, sleep).await;
                }
                None => {
                    platform::time::sleep_cycles(platform::time::wall::ns_to_cycles(1_000_000))
                        .await
                }
            }
        }
    }
}

/// Netif TX: the stack hands one Ethernet frame (borrowed for this call).
extern "C" fn tx_callback(_dev: u64, frame: *const u8, len: usize) -> i32 {
    let Some(dev) = netdev() else {
        return ENODEV;
    };
    if frame.is_null() || len < 14 || !dev.up.load(Ordering::Acquire) {
        return ENOBUFS;
    }
    // SAFETY: the bridge lends `len` readable bytes for the call.
    let bytes = unsafe { core::slice::from_raw_parts(frame, len) }.to_vec();
    let mut queue = dev.tx.lock();
    if queue.len() >= TX_QUEUE_MAX {
        return ENOBUFS;
    }
    queue.push_back(bytes);
    0
}

/// Family-host events: queue the work on the executor and accept it; the
/// outcome is reported when it completes.
extern "C" fn event_callback(_dev: u64, event: u32, payload: *const u8, len: usize) -> i32 {
    let Some(dev) = netdev() else {
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
            let Some(request) = decode_scan_request(&bytes) else {
                return EINVAL;
            };
            platform::spawn(async move { scan_and_report(&dev, request).await });
            0
        }
        wifi::EVENT_CONNECT => {
            let Some(request) = decode_connect(&bytes) else {
                return EINVAL;
            };
            platform::spawn(async move {
                let (bssid, frequency) = (request.bssid, request.frequency_mhz);
                if let Err(error) = dev.associate(request).await {
                    log(format_args!("connect failed: {error:?}"));
                    let _ = dev.report(
                        wifi::OP_CONNECT_RESULT,
                        &encode_connect_result(wifi::STATUS_UNSPECIFIED_FAILURE, bssid, frequency),
                    );
                }
            });
            0
        }
        wifi::EVENT_DISCONNECT => {
            platform::spawn(async move {
                let was_up = dev.up.load(Ordering::Acquire);
                let _ = dev.disassociate().await;
                // A disconnect while not associated still completes the
                // host's wait.
                if !was_up {
                    let _ = dev.report(
                        wifi::OP_DISCONNECTED,
                        &encode_disconnected(wifi::REASON_DEAUTH_LEAVING, true),
                    );
                }
            });
            0
        }
        // The station's escan has no cancellation hook here; the result of
        // an aborted scan is discarded by the host.
        wifi::EVENT_SCAN_ABORT => 0,
        _ => EOPNOTSUPP,
    }
}

async fn scan_and_report(dev: &ModuleNetdev, request: ScanRequest) {
    let status = match dev.scan(request).await {
        Ok(results) => {
            for (bss, ies) in results {
                let _ = dev.report(wifi::OP_SCAN_RESULT, &encode_scan_result(&bss, &ies));
            }
            0i32
        }
        Err(Error::Busy) => -16,
        Err(Error::Unsupported | Error::Malformed) => -22,
        Err(_) => -5,
    };
    let _ = dev.report(wifi::OP_SCAN_DONE, &status.to_le_bytes());
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
    let security = match security {
        wifi::SECURITY_OPEN => SecurityConfig::Open,
        wifi::SECURITY_PSK => SecurityConfig::Wpa2 {
            psk: secret.try_into().ok()?,
        },
        wifi::SECURITY_SAE => SecurityConfig::Wpa3 {
            password: secret.to_vec(),
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

/// `REGISTER_WIPHY` from the station: its policy-admitted channels, the
/// PHY capabilities firmware reported, the built-in shell's cipher list
/// (`interface.rs::cipher_suites`) and the firmware SME offloads.
fn encode_register_wiphy(ifindex: u32, station: &ModuleStation) -> Option<Vec<u8>> {
    let (mut b2, mut b5) = (Vec::new(), Vec::new());
    for &channel in &station.channels {
        let list = if channel <= 14 { &mut b2 } else { &mut b5 };
        if channel != 0 && list.len() < 64 && !list.contains(&channel) {
            list.push(channel);
        }
    }
    let mut hw = 0u8;
    if station.ht_capabilities().iter().any(Option::is_some) {
        hw |= 1;
    }
    if station.vht_capabilities().iter().any(Option::is_some) {
        hw |= 2;
    }
    let ciphers: &[u32] = if station.supports_management_protection() {
        &[
            narf_wireless::CIPHER_SUITE_CCMP,
            narf_wireless::CIPHER_SUITE_AES_CMAC,
        ]
    } else if station.supplicant {
        &[narf_wireless::CIPHER_SUITE_CCMP]
    } else {
        &[]
    };
    let mut flags = wifi::FLAG_REPORTS_DISCONNECT;
    if station.supplicant {
        flags |= wifi::FLAG_PSK_OFFLOAD;
    }
    if station.supports_sae_offload() {
        flags |= wifi::FLAG_SAE_OFFLOAD;
    }
    let bands: Vec<(u32, &Vec<u8>)> = [(2412u32, &b2), (5180, &b5)]
        .into_iter()
        .filter(|(_, list)| !list.is_empty())
        .collect();
    if bands.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    out.extend_from_slice(&ifindex.to_le_bytes());
    out.extend_from_slice(&station.mac);
    out.extend_from_slice(&1u32.to_le_bytes()); // STATION
    out.push(hw);
    out.push(ciphers.len() as u8);
    out.push(bands.len() as u8);
    out.push(flags);
    out.push(16); // max scan SSIDs (the built-in shell's)
    out.push(0);
    out.extend_from_slice(&512u16.to_le_bytes());
    for c in ciphers {
        out.extend_from_slice(&c.to_le_bytes());
    }
    for (freq, list) in bands {
        out.extend_from_slice(&freq.to_le_bytes());
        out.push(list.len() as u8);
        out.push(0);
        out.extend_from_slice(list);
    }
    Some(out)
}

/// Initialize the station on the attached transport and publish it (the
/// module build's `interface::attach_runtime`): firmware IOCTLs, country,
/// PHY and event setup under the fixed signed domain, then the session,
/// the netdev, the wiphy, the service loop and, with `brcm.ssid=`, the
/// autoconnect.
pub async fn attach(
    adapter: ModuleAdapter,
    domain: Arc<narf_wireless::reg::RegulatoryDomain>,
) -> Result<(), &'static str> {
    let station = ModuleStation::initialize_live(
        alloc::boxed::Box::new(adapter),
        &[],
        Arc::new(FixedPolicy(domain.clone())),
    )
    .await
    .map_err(|_| "station initialization failed")?;
    let dev_token = platform::device();
    let mut session = 0u64;
    // SAFETY: `event_callback` is a valid extern "C" fn in this image;
    // `session` is a live local.
    let rc = unsafe {
        ffi::narf_wireless_open_with_event(
            dev_token,
            wifi::FAMILY,
            wifi::VERSION,
            event_callback as usize,
            &mut session,
        )
    };
    if rc != 0 {
        return Err("wireless session refused; no wlan interface");
    }
    let mac = station.mac;
    let mut ifindex = 0u32;
    // SAFETY: `mac` names six readable bytes; `tx_callback` is a valid
    // extern "C" fn in this image; `ifindex` is a live local.
    let rc = unsafe {
        ffi::narf_netif_register_with_context(
            dev_token,
            mac.as_ptr(),
            tx_callback as usize,
            &mut ifindex,
        )
    };
    if rc != 0 {
        return Err("netdev registration refused");
    }
    let wiphy = encode_register_wiphy(ifindex, &station).ok_or("no admitted channel")?;
    let dev = Arc::new(ModuleNetdev {
        mac,
        ifindex,
        session,
        station: Mutex::new(station),
        bssid: AtomicU64::new(0),
        up: AtomicBool::new(false),
        failed: AtomicBool::new(false),
        dead: AtomicBool::new(false),
        resets: AtomicU32::new(0),
        domain: domain.clone(),
        retained: IrqSafeSpinLock::new(None),
        tx: IrqSafeSpinLock::new(VecDeque::new()),
    });
    *NETDEV.lock() = Some(dev.clone());
    let rc = dev.report(wifi::OP_REGISTER_WIPHY, &wiphy);
    if rc != 0 {
        log(format_args!("wiphy registration refused ({rc})"));
    }
    log(format_args!(
        "station up: wlan (ifindex {ifindex}) mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    ));
    platform::spawn(dev.clone().run());
    if let Some(target) = autoconnect_request() {
        platform::spawn(autoconnect(dev, target));
    }
    Ok(())
}

// ── Bring-up aid: `brcm.ssid=` / `brcm.psk=` / `brcm.passphrase=` ──────

/// The load parameters: the SSID and the PMK (`None` = open network).
struct Autoconnect {
    ssid: Vec<u8>,
    pmk: Option<[u8; 32]>,
}

impl Autoconnect {
    /// A connect request with the BSS left to the last scan.
    fn request(&self) -> AssociateRequest {
        AssociateRequest {
            bssid: [0; 6],
            ssid: self.ssid.clone(),
            frequency_mhz: 0,
            channel: 0,
            security: match self.pmk {
                Some(psk) => SecurityConfig::Wpa2 { psk },
                None => SecurityConfig::Open,
            },
            ie: Vec::new(),
        }
    }
}

/// The load parameters (`brcm.ssid=` and friends).
/// `psk` is 64 hex digits (the PMK); `passphrase` 8..=63 characters is
/// hashed with the SSID (IEEE 802.11 PBKDF2-SHA1, 4096 rounds); neither
/// means an open network.
fn autoconnect_request() -> Option<Autoconnect> {
    let param = |name: &str| narf_module_rt::param::get(name).unwrap_or_default();
    let ssid = param("ssid");
    if ssid.is_empty() || ssid.len() > 32 {
        return None;
    }
    let (psk, passphrase) = (param("psk"), param("passphrase"));
    let pmk = if psk.len() == 64 {
        let mut pmk = [0u8; 32];
        for (i, byte) in pmk.iter_mut().enumerate() {
            *byte = u8::from_str_radix(psk.get(2 * i..2 * i + 2)?, 16).ok()?;
        }
        Some(pmk)
    } else if (8..=63).contains(&passphrase.len()) {
        Some(narf_crypto::pbkdf2_sha1::wpa2_pmk(
            passphrase.as_bytes(),
            ssid.as_bytes(),
        ))
    } else if psk.is_empty() && passphrase.is_empty() {
        None
    } else {
        log(format_args!(
            "ignoring brcm.* parameters: psk must be 64 hex digits, passphrase 8..63"
        ));
        return None;
    };
    Some(Autoconnect {
        ssid: ssid.into_bytes(),
        pmk,
    })
}

/// Scan for the SSID, then join the strongest match; up to five tries.
async fn autoconnect(dev: Arc<ModuleNetdev>, target: Autoconnect) {
    let name = String::from_utf8_lossy(&target.ssid).into_owned();
    for attempt in 0..5u64 {
        if attempt > 0 {
            platform::time::sleep_cycles(platform::time::wall::ns_to_cycles(
                2_000_000_000 * attempt,
            ))
            .await;
        }
        if dev.connected().is_some() || dev.dead.load(Ordering::Acquire) {
            return;
        }
        let scan = ScanRequest {
            ssids: alloc::vec![target.ssid.clone()],
            frequencies_mhz: Vec::new(),
            channels: Vec::new(),
            active: true,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: None,
            duration_mandatory: false,
            extra_ies: Vec::new(),
        };
        if let Err(error) = dev.scan(scan).await {
            log(format_args!(
                "autoconnect scan for {name:?} failed: {error:?}"
            ));
            continue;
        }
        match dev.associate(target.request()).await {
            Ok((bssid, frequency)) => {
                log(format_args!(
                    "autoconnect joined {name:?} at {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} \
                     ({frequency} MHz)",
                    bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]
                ));
                return;
            }
            Err(error) => log(format_args!(
                "autoconnect join of {name:?} failed: {error:?}"
            )),
        }
    }
}
