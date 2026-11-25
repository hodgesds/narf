//! The module build's netdev (`mt76.ko`): the station data path and control
//! plane behind the KABI.
//!
//! Built in, [`crate::iface`] is the full mac80211-shaped netdev (frame rings,
//! AP/P2P/monitor roles, WoW and system PM, scheduled scan, CQM, survey). A
//! module reaches the network stack only through the netif bridge and the
//! `WIFI` family host (`wireless/src/module_host.rs`, version 2), so this is
//! the station subset over the same retained firmware owner
//! (`mt7921::firmware_transport`) the built-in netdev drives, through the same
//! boot-owner entry points and the same scan/join helpers
//! ([`crate::iface_station`]):
//!
//! - **netdev** — `narf_netif_register_with_context` (the bridge names it
//!   `wlan%d` because the device has a wireless session); TX frames arrive in
//!   [`tx_callback`], RX leaves through `narf_netif_rx`;
//! - **wiphy** — `REGISTER_WIPHY` binds the shell to that netdev and
//!   advertises the firmware-reported bands, HT/VHT, the eight cipher suites
//!   and the in-driver SME (PSK and SAE offload, disconnect reports);
//! - **control** — the host's `SCAN_REQUEST` / `CONNECT` / `DISCONNECT`
//!   events run [`ModuleNetdev::scan`] / [`ModuleNetdev::associate`] /
//!   [`ModuleNetdev::disassociate`] (the station owner does WPA2-PSK and
//!   WPA3-SAE with PMF itself), answered with `SCAN_RESULT` / `SCAN_DONE` /
//!   `CONNECT_RESULT` / `DISCONNECTED`;
//! - **data** — the service task is the built-in worker pass: mask and
//!   acknowledge the device sources, one packet step (queued TX, a batch of
//!   RX), key service, unmask; a peer or firmware loss is reported as
//!   `DISCONNECTED` with mac80211's reason, and the built-in recovery
//!   schedule (1 s, 5 s, 30 s) resets the radio.
//!
//! Not carried (built-in only): AP, P2P and monitor roles; WoW and system PM;
//! scheduled scan; roaming; CQM, survey and station statistics; power-save
//! control; the association-comeback event; the userspace SME.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use core::task::{Context, Poll};

use narf_wireless::scan::BssSecurity;
use narf_wireless::{AssociateRequest, ScanRequest, SecurityConfig, WirelessError};

use crate::iface_station::{
    active_channels, bss_info, resolve_join, scan_channels, scan_frequency, six_ghz_scan_ids,
    transmit_admitted, validate_join, CIPHER_SUITES,
};
use crate::mt7921::firmware_transport::{self as transport, Error, RadioInfo, ScanBss};
use crate::mt7921::irq::LINE;
use crate::platform::{self, Console, IrqSafeSpinLock, Mutex};

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

/// `WIFI` family host, version 2 (`modules/DATAPATH_ABI_DESIGN.md`).
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
    pub const MODE_STATION: u32 = 1;
    pub const HW_HT: u8 = 1;
    pub const HW_VHT: u8 = 2;
    pub const FLAG_PSK_OFFLOAD: u8 = 0x01;
    pub const FLAG_SAE_OFFLOAD: u8 = 0x02;
    pub const FLAG_REPORTS_DISCONNECT: u8 = 0x04;
    pub const SECURITY_OPEN: u8 = 0;
    pub const SECURITY_PSK: u8 = 1;
    pub const SECURITY_SAE: u8 = 2;
    /// IEEE 802.11 status: unspecified failure.
    pub const STATUS_UNSPECIFIED_FAILURE: u16 = 1;
    /// IEEE 802.11 reasons: unspecified; deauthenticated because leaving.
    pub const REASON_UNSPECIFIED: u16 = 1;
    pub const REASON_DEAUTH_LEAVING: u16 = 3;
}

/// TX frames queued between the stack and the service task.
const TX_QUEUE_MAX: usize = 512;
/// The built-in worker's polled period and watchdog (`MT792x_WATCHDOG_TIME`).
const POLL_NS: u64 = 1_000_000;
const WATCHDOG_NS: u64 = 250_000_000;
/// The built-in `max_scan_ssids`.
const MAX_SCAN_SSIDS: u8 = 4;
const ENOBUFS: i32 = -105;

/// The station netdev of the module build.
#[allow(missing_debug_implementations)]
pub struct ModuleNetdev {
    radio: RadioInfo,
    ifindex: u32,
    session: u64,
    /// Serializes scan / connect / disconnect / teardown, as the built-in
    /// netdev's `control` mutex does.
    control: Mutex<()>,
    scan_cache: IrqSafeSpinLock<Vec<ScanBss>>,
    scan_beaconed: IrqSafeSpinLock<Vec<([u8; 6], u8)>>,
    bssid: IrqSafeSpinLock<Option<[u8; 6]>>,
    frequency: AtomicU32,
    /// The firmware still holds a station BSS to leave (built-in
    /// `teardown_needed`).
    teardown_needed: AtomicBool,
    /// Module exit: stop servicing.
    dead: AtomicBool,
    tx: IrqSafeSpinLock<VecDeque<Vec<u8>>>,
    pending_tx: IrqSafeSpinLock<Option<Vec<u8>>>,
    /// A packet step moved frames: run the pass again at once.
    serviced: AtomicBool,
    recovery_attempts: AtomicU32,
    recovery_after_ns: AtomicU64,
}

/// The one radio. Callbacks find it here.
static NETDEV: IrqSafeSpinLock<Option<Arc<ModuleNetdev>>> = IrqSafeSpinLock::new(None);

fn netdev() -> Option<Arc<ModuleNetdev>> {
    NETDEV.lock().clone()
}

fn log(args: core::fmt::Arguments<'_>) {
    let _ = writeln!(Console, "  mt76.ko: {}", args);
}

fn wireless_error(error: Error) -> WirelessError {
    match error {
        Error::Bounds => WirelessError::InvalidArgs,
        Error::Busy => WirelessError::Busy,
        Error::Timeout => WirelessError::Timeout,
        Error::Authority => WirelessError::Denied,
        _ => WirelessError::HardwareError,
    }
}

/// The built-in `radio_needs_recovery`.
fn radio_needs_recovery() -> bool {
    use transport::{boot_status, BootStatus, State};
    matches!(
        boot_status(),
        BootStatus::Retained(State::Failed { .. } | State::Running(_) | State::Stopped)
    )
}

impl ModuleNetdev {
    fn mac(&self) -> [u8; 6] {
        self.radio.capabilities.mac
    }

    fn link_up(&self) -> bool {
        self.bssid.lock().is_some()
    }

    fn dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
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

    /// The built-in `clear_link`, station subset.
    fn clear_link(&self) {
        *self.bssid.lock() = None;
        self.frequency.store(0, Ordering::Release);
        *self.pending_tx.lock() = None;
        self.tx.lock().clear();
    }

    /// The built-in `lose_link`: the link ended without an operator request,
    /// reported with the reason and origin the station owner recorded (a peer
    /// loss), or mac80211's `WLAN_REASON_UNSPECIFIED` for a firmware or
    /// transport failure. The firmware teardown follows in the service pass.
    fn lose_link(&self) {
        let connected = self.link_up();
        let loss = connected.then(transport::boot_link_loss).flatten();
        if connected {
            self.teardown_needed.store(true, Ordering::Release);
        }
        self.clear_link();
        if connected {
            let (reason, from_ap) =
                loss.map_or((wifi::REASON_UNSPECIFIED, false), |l| (l.reason, l.from_ap));
            if loss.is_none() {
                log(format_args!("connection lost"));
            }
            let _ = self.report(
                wifi::OP_DISCONNECTED,
                &encode_disconnected(reason, !from_ap),
            );
        }
    }

    /// The built-in `finish_teardown_inner`: leave a BSS the firmware still
    /// holds, and reset a failed radio on the built-in recovery schedule
    /// (`operator_request` skips the schedule, as a new scan or connect does).
    async fn finish_teardown(&self, operator_request: bool) -> Result<(), WirelessError> {
        if self.teardown_needed.load(Ordering::Acquire) {
            match transport::disassociate_boot_station().await {
                Ok(()) => {
                    self.teardown_needed.store(false, Ordering::Release);
                    self.recovery_attempts.store(0, Ordering::Release);
                    self.recovery_after_ns.store(0, Ordering::Release);
                }
                Err(_) if radio_needs_recovery() => {}
                Err(Error::Busy) => return Err(WirelessError::Busy),
                Err(_) => return Err(WirelessError::HardwareError),
            }
        }
        if !radio_needs_recovery() {
            return Ok(());
        }
        let now = platform::time::monotonic_ns();
        let attempts = self.recovery_attempts.load(Ordering::Acquire);
        if !operator_request
            && (attempts >= 3 || now < self.recovery_after_ns.load(Ordering::Acquire))
        {
            return Err(WirelessError::Busy);
        }
        self.recovery_attempts
            .store(attempts.saturating_add(1), Ordering::Release);
        let delay = match attempts {
            0 => 1_000_000_000,
            1 => 5_000_000_000,
            _ => 30_000_000_000,
        };
        self.recovery_after_ns
            .store(now.saturating_add(delay), Ordering::Release);
        self.lose_link();
        self.teardown_needed.store(true, Ordering::Release);
        self.scan_cache.lock().clear();
        self.scan_beaconed.lock().clear();
        log(format_args!(
            "radio failed; recovering (attempt {})",
            attempts + 1
        ));
        transport::recover_boot_radio(self.mac())
            .await
            .map_err(|_| WirelessError::HardwareError)?;
        self.teardown_needed.store(false, Ordering::Release);
        self.recovery_attempts.store(0, Ordering::Release);
        self.recovery_after_ns.store(0, Ordering::Release);
        Ok(())
    }

    /// The built-in netdev's `scan`, station subset.
    pub async fn scan(&self, req: ScanRequest) -> Result<Vec<ScanBss>, WirelessError> {
        if self.dead() {
            return Err(WirelessError::HardwareError);
        }
        let six = crate::mt7921::six_ghz::qualified(self.radio);
        let mut channels = scan_channels(&req, self.radio.capabilities.phy.bands, six)?;
        // WIPHY_FLAG_SPLIT_SCAN_6GHZ: 2.4/5 GHz first, then the 6 GHz
        // channels their Reduced Neighbor Reports select.
        let requested_6ghz: Vec<u8> = channels.iter().copied().filter(|&id| id > 180).collect();
        channels.retain(|&id| id <= 180);
        let ssids = if req.active && !channels.is_empty() {
            let domain = platform::reg_db::ensure_domain().map_err(|_| WirelessError::Denied)?;
            channels = active_channels(&req, channels, &domain)?;
            if req.ssids.is_empty() {
                alloc::vec![Vec::new()]
            } else {
                req.ssids.clone()
            }
        } else {
            Vec::new()
        };
        let _control = self.control.lock().await;
        if self.link_up() {
            if req.random_mac.is_some() {
                return Err(WirelessError::Busy);
            }
        } else {
            self.finish_teardown(true).await?;
        }
        let result = async {
            use transport::{scan_boot_with_options, ScanOptions};
            let mut found = Vec::new();
            let mut beaconed = Vec::new();
            if !channels.is_empty() {
                let report = scan_boot_with_options(
                    &channels,
                    &ssids,
                    ScanOptions {
                        extra_ies: &req.extra_ies,
                        random_mac: req.random_mac,
                    },
                )
                .await
                .map_err(wireless_error)?;
                found = report.bss;
                beaconed = report.beaconed;
            }
            let six_ids = six_ghz_scan_ids(&req, &requested_6ghz, &found);
            if !six_ids.is_empty() {
                // 6 GHz channels are scanned passively under a NO_IR domain.
                let report = scan_boot_with_options(
                    &six_ids,
                    &[],
                    ScanOptions {
                        extra_ies: &[],
                        random_mac: req.random_mac,
                    },
                )
                .await
                .map_err(wireless_error)?;
                found.extend(report.bss);
                beaconed.extend(report.beaconed);
            }
            *self.scan_cache.lock() = found.clone();
            *self.scan_beaconed.lock() = beaconed;
            Ok(found)
        }
        .await;
        if result.is_err() && radio_needs_recovery() {
            self.lose_link();
        }
        result
    }

    /// A `CONNECT` that left the BSS or its frequency to the driver: the
    /// strongest matching network of the last scan (`cfg80211_get_bss`).
    fn resolve_bss(&self, mut req: AssociateRequest) -> Option<AssociateRequest> {
        let scan = self.scan_cache.lock();
        let wanted = |bss: &ScanBss| {
            let security = crate::iface_station::scan_security(bss);
            bss.ssid == req.ssid
                && (req.bssid == [0; 6] || bss.bssid == req.bssid)
                && (req.frequency_mhz == 0 || scan_frequency(bss) == Some(req.frequency_mhz))
                && match &req.security {
                    SecurityConfig::Open => matches!(security, BssSecurity::Open),
                    SecurityConfig::Wpa2 { .. } => matches!(security, BssSecurity::Wpa2),

                    SecurityConfig::Wpa3 { .. } => {
                        matches!(security, BssSecurity::Wpa3 | BssSecurity::Wpa2)
                    }
                    SecurityConfig::External(_) => false,
                }
        };
        let bss = scan
            .iter()
            .filter(|bss| wanted(bss))
            .max_by_key(|bss| bss.signal_dbm.unwrap_or(-128))?;
        req.bssid = bss.bssid;
        req.frequency_mhz = scan_frequency(bss)?;
        req.channel = u32::from(bss.channel);
        Some(req)
    }

    /// The built-in netdev's `associate`: validation, the previous link's
    /// teardown, BSS/security resolution against the scan cache and the
    /// current regulatory grant, then the station owner's join (open, or the
    /// in-driver WPA2-PSK / WPA3-SAE handshake).
    pub async fn associate(&self, mut req: AssociateRequest) -> Result<(), WirelessError> {
        let _control = self.control.lock().await;
        let six = validate_join(self.radio, &req)?;
        self.finish_teardown(true).await?;
        if self.link_up() {
            return Err(WirelessError::Busy);
        }
        let security = core::mem::replace(&mut req.security, SecurityConfig::Open);
        let (bss, security, heard_beacon) = {
            let scan = self.scan_cache.lock().clone();
            let beaconed = self.scan_beaconed.lock().clone();
            resolve_join(self.radio, &scan, &beaconed, &req, security, six, true)?
        };
        transport::associate_boot_station_as(
            &bss,
            &req.ssid,
            security,
            &req.ie,
            false,
            heard_beacon,
        )
        .await
        .map_err(|error| {
            log(format_args!("join failed: {error:?}"));
            wireless_error(error)
        })?;
        *self.bssid.lock() = Some(req.bssid);
        self.frequency.store(req.frequency_mhz, Ordering::Release);
        let _ = self.report(
            wifi::OP_CONNECT_RESULT,
            &encode_connect_result(0, req.bssid, req.frequency_mhz),
        );
        LINE.raise();
        Ok(())
    }

    /// The built-in netdev's `disassociate`.
    pub async fn disassociate(&self) -> Result<(), WirelessError> {
        let _control = self.control.lock().await;
        self.finish_teardown(true).await?;
        if !self.link_up() {
            return Ok(());
        }
        self.teardown_needed.store(true, Ordering::Release);
        self.clear_link();
        transport::disassociate_boot_station()
            .await
            .map_err(wireless_error)?;
        self.teardown_needed.store(false, Ordering::Release);
        Ok(())
    }

    /// Deliver one received Ethernet frame to the stack (`narf_netif_rx`).
    fn deliver(&self, mut frame: Vec<u8>) {
        // SAFETY: `frame` names `len` bytes the call may rewrite in place.
        let _ = unsafe {
            ffi::narf_netif_rx(
                platform::device(),
                self.ifindex,
                frame.as_mut_ptr(),
                frame.len(),
            )
        };
    }

    /// The built-in `station_step`: one queued TX frame and a batch of
    /// received frames. `None` when the owner was busy with control work.
    fn station_step(&self) -> Result<Option<u32>, WirelessError> {
        if !self.link_up() {
            return Ok(Some(0));
        }
        let result = {
            let mut pending = self.pending_tx.lock();
            if pending.is_none() {
                *pending = self.tx.lock().pop_front();
            }
            let result = transport::step_boot_network(pending.as_deref());
            if result.as_ref().is_ok_and(|step| step.transmitted) {
                *pending = None;
            }
            result
        };
        let step = match result {
            Ok(step) => step,
            Err(Error::Busy) => return Ok(None),
            Err(error) => {
                if error != Error::DeviceGone {
                    log(format_args!("packet service failed: {error:?}"));
                }
                self.lose_link();
                return Err(WirelessError::HardwareError);
            }
        };
        let moved = u32::from(step.transmitted) + step.received.len() as u32;
        let epoch = step.receive_epoch;
        for frame in step.received {
            // A key or association fence since the step retires the batch
            // (the built-in `deliver_received_batch` epoch rule).
            match transport::boot_receive_current(epoch) {
                Ok(true) => {}
                Ok(false) => break,
                Err(_) => {
                    self.lose_link();
                    return Err(WirelessError::HardwareError);
                }
            }
            let mut slot = Some(frame);
            match transport::boot_receive_publish(epoch, || {
                if let Some(frame) = slot.take() {
                    self.deliver(frame);
                }
            }) {
                Ok(_) => {}
                Err(_) => {
                    self.lose_link();
                    return Err(WirelessError::HardwareError);
                }
            }
        }
        Ok(Some(moved))
    }

    /// The built-in `poll_data`, station subset: teardown/recovery, the
    /// packet step and the key/control service of an associated link.
    async fn poll_data(&self) {
        if self.teardown_needed.load(Ordering::Acquire) || radio_needs_recovery() {
            if let Some(_control) = self.control.try_lock() {
                let _ = self.finish_teardown(false).await;
            }
        }
        if !self.link_up() {
            return;
        }
        if let Ok(Some(moved)) = self.station_step() {
            if moved != 0 {
                self.serviced.store(true, Ordering::Release);
            }
        }
        if self.link_up() {
            let Some(_control) = self.control.try_lock() else {
                return;
            };
            match transport::service_boot_keys().await {
                Ok(()) | Err(Error::Busy) => {}
                Err(error) => {
                    if error != Error::DeviceGone {
                        log(format_args!("key/control service failed: {error:?}"));
                    }
                    self.lose_link();
                }
            }
        }
    }

    /// The built-in `service_pass`: mask and acknowledge the sources, poll,
    /// unmask; repoll at once after moving frames, else sleep until the line
    /// is raised or the station's next timed work (polled: 1 ms).
    async fn service_pass(&self) {
        let seen = LINE.raised();
        let owned = transport::boot_interrupts_begin().is_ok();
        self.poll_data().await;
        let owned = owned && transport::boot_interrupts_end().is_ok();
        if self.serviced.swap(false, Ordering::AcqRel) {
            platform::yield_now().await;
            return;
        }
        let period = if owned && LINE.bound() {
            match transport::boot_service_deadline() {
                Ok(Some(at)) => at
                    .saturating_sub(platform::time::monotonic_ns())
                    .clamp(POLL_NS, WATCHDOG_NS),
                Ok(None) => WATCHDOG_NS,
                Err(_) => POLL_NS,
            }
        } else {
            POLL_NS
        };
        RaiseOrSleep {
            wait: LINE.wait(seen),
            sleep: platform::time::sleep_ns(period),
        }
        .await;
    }

    async fn run(self: Arc<Self>) {
        while !self.dead() {
            self.service_pass().await;
        }
    }
}

/// The line's next raise or a timeout, whichever comes first (the built-in
/// `narf_time::timeout(deadline, LINE.wait(seen))`).
struct RaiseOrSleep<'a> {
    wait: crate::mt7921::irq::Wait<'a>,
    sleep: platform::time::SleepUntil,
}

impl Future for RaiseOrSleep<'_> {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if Pin::new(&mut self.wait).poll(cx).is_ready() {
            return Poll::Ready(());
        }
        Pin::new(&mut self.sleep).poll(cx)
    }
}

/// Netif TX: the stack hands one Ethernet frame (borrowed for this call).
extern "C" fn tx_callback(_dev: u64, frame: *const u8, len: usize) -> i32 {
    let Some(dev) = netdev() else {
        return -19;
    };
    if frame.is_null() || !(14..=1514).contains(&len) || !dev.link_up() {
        return ENOBUFS;
    }
    // SAFETY: the bridge lends `len` readable bytes for the call.
    let bytes = unsafe { core::slice::from_raw_parts(frame, len) };
    if !transmit_admitted(bytes, dev.mac()) {
        return ENOBUFS;
    }
    {
        let mut queue = dev.tx.lock();
        if queue.len() >= TX_QUEUE_MAX {
            return ENOBUFS;
        }
        queue.push_back(bytes.to_vec());
    }
    // `ieee80211_tx` -> `mt76_worker_schedule`: service the frame now.
    LINE.raise();
    0
}

/// Family-host events: queue the work on the executor and accept it; the
/// outcome is reported when it completes.
extern "C" fn event_callback(_dev: u64, event: u32, payload: *const u8, len: usize) -> i32 {
    let Some(dev) = netdev() else {
        return -19;
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
                return -22;
            };
            platform::spawn(async move { scan_and_report(&dev, req).await });
            0
        }
        wifi::EVENT_CONNECT => {
            let Some(req) = decode_connect(&bytes) else {
                return -22;
            };
            platform::spawn(async move {
                let (bssid, frequency) = (req.bssid, req.frequency_mhz);
                let result = match dev.resolve_bss(req) {
                    Some(req) => dev.associate(req).await,
                    None => Err(WirelessError::InvalidArgs),
                };
                if let Err(error) = result {
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
                let _ = dev.disassociate().await;
                // A disconnect while not associated still completes the
                // host's wait.
                let _ = dev.report(
                    wifi::OP_DISCONNECTED,
                    &encode_disconnected(wifi::REASON_DEAUTH_LEAVING, true),
                );
            });
            0
        }
        // A firmware scan runs to its end; the host discards an aborted
        // scan's results.
        wifi::EVENT_SCAN_ABORT => 0,
        _ => -95,
    }
}

async fn scan_and_report(dev: &ModuleNetdev, req: ScanRequest) {
    let status = match dev.scan(req).await {
        Ok(results) => {
            for bss in &results {
                let _ = dev.report(wifi::OP_SCAN_RESULT, &encode_scan_result(bss));
            }
            0i32
        }
        Err(WirelessError::Busy) => -16,
        Err(WirelessError::InvalidArgs) => -22,
        Err(WirelessError::NotSupported) => -95,
        Err(WirelessError::Denied) => -13,
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

fn encode_scan_result(bss: &ScanBss) -> Vec<u8> {
    let info = bss_info(bss);
    let ssid = &info.ssid[..info.ssid.len().min(32)];
    let ies = &bss.information_elements[..bss.information_elements.len().min(2048)];
    let mut out = Vec::with_capacity(20 + ssid.len() + ies.len());
    out.extend_from_slice(&info.bssid);
    out.push(bss.channel);
    out.push(security_wire(info.security));
    out.extend_from_slice(&info.frequency_mhz.to_le_bytes());
    out.push(info.rssi.clamp(-128, 127) as i8 as u8);
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
    let channel = crate::mt7921::channel::from_frequency(frequency_mhz).map_or(0, u32::from);
    Some(AssociateRequest {
        bssid,
        ssid,
        frequency_mhz,
        channel,
        security,
        ie,
    })
}

/// `REGISTER_WIPHY` from the firmware-reported radio (the built-in
/// `get_wireless_info` / `cipher_suites` / `max_scan_*`, station subset).
fn encode_register_wiphy(ifindex: u32, radio: RadioInfo) -> Vec<u8> {
    let bands = crate::iface_station::bands(radio);
    let mut hw = 0u8;
    if radio.capabilities.phy.ht {
        hw |= wifi::HW_HT;
    }
    if crate::mt7921::vht::qualified(radio) {
        hw |= wifi::HW_VHT;
    }
    let mut out = Vec::new();
    out.extend_from_slice(&ifindex.to_le_bytes());
    out.extend_from_slice(&radio.capabilities.mac);
    out.extend_from_slice(&wifi::MODE_STATION.to_le_bytes());
    out.push(hw);
    out.push(CIPHER_SUITES.len() as u8);
    out.push(bands.len() as u8);
    out.push(wifi::FLAG_PSK_OFFLOAD | wifi::FLAG_SAE_OFFLOAD | wifi::FLAG_REPORTS_DISCONNECT);
    out.push(MAX_SCAN_SSIDS);
    out.push(0);
    out.extend_from_slice(&transport::MAX_SCAN_IE_LEN.to_le_bytes());
    for suite in CIPHER_SUITES {
        out.extend_from_slice(&suite.to_le_bytes());
    }
    for band in &bands {
        let channels: Vec<u8> = band
            .channels
            .iter()
            .filter_map(|&c| u8::try_from(c).ok())
            .take(64)
            .collect();
        out.extend_from_slice(&band.freq_mhz.to_le_bytes());
        out.push(channels.len() as u8);
        out.push(0);
        out.extend_from_slice(&channels);
    }
    out
}

/// Publish the initialized radio's netdev and wiphy (the built-in
/// `register_scan_iface_profile`): session, netdev, wiphy, then the service
/// task. A repeat (provisioning after a verified recovery) of the same radio
/// keeps the published netdev.
pub fn register(info: RadioInfo) -> Result<(), WirelessError> {
    if let Some(existing) = netdev() {
        return if existing.mac() == info.capabilities.mac {
            Ok(())
        } else {
            Err(WirelessError::Busy)
        };
    }
    let mac = info.capabilities.mac;
    if mac == [0; 6] || mac[0] & 1 != 0 {
        return Err(WirelessError::InvalidArgs);
    }
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
        log(format_args!(
            "wireless session refused ({rc}); no wlan interface"
        ));
        return Err(WirelessError::Denied);
    }
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
        log(format_args!("netdev registration refused ({rc})"));
        return Err(WirelessError::Denied);
    }
    let dev = Arc::new(ModuleNetdev {
        radio: info,
        ifindex,
        session,
        control: Mutex::new(()),
        scan_cache: IrqSafeSpinLock::new(Vec::new()),
        scan_beaconed: IrqSafeSpinLock::new(Vec::new()),
        bssid: IrqSafeSpinLock::new(None),
        frequency: AtomicU32::new(0),
        teardown_needed: AtomicBool::new(false),
        dead: AtomicBool::new(false),
        tx: IrqSafeSpinLock::new(VecDeque::new()),
        pending_tx: IrqSafeSpinLock::new(None),
        serviced: AtomicBool::new(false),
        recovery_attempts: AtomicU32::new(0),
        recovery_after_ns: AtomicU64::new(0),
    });
    let rc = dev.report(
        wifi::OP_REGISTER_WIPHY,
        &encode_register_wiphy(ifindex, info),
    );
    if rc != 0 {
        log(format_args!("wiphy registration refused ({rc})"));
    }
    *NETDEV.lock() = Some(dev.clone());
    platform::spawn(dev.run());
    log(format_args!(
        "wlan (ifindex {ifindex}) mac {:02x?}, bands {:#x}",
        mac, info.capabilities.phy.bands
    ));
    Ok(())
}

/// Module exit: stop servicing and forget the netdev. Device teardown closes
/// the session (reporting the disconnect and the interface removal) and
/// unregisters the netdev.
pub fn withdraw() {
    if let Some(dev) = NETDEV.lock().take() {
        dev.dead.store(true, Ordering::Release);
        dev.clear_link();
    }
    LINE.raise();
}
