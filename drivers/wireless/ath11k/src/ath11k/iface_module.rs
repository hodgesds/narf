//! The module build's netdev (`ath11k.ko`): the station data path and
//! control plane behind the KABI.
//!
//! Built in, [`super::iface`] is a full mac80211-shaped netdev (frame
//! rings, AP/P2P/monitor roles, WoW and system PM, virtual interfaces,
//! external-SME MLME and control port). A module reaches the network stack
//! only through the netif bridge and the `WIFI` family host
//! (`wireless/src/module_host.rs`, version 2), so this is the station
//! subset over the same runtime ([`Shared`]) and MAC ([`Mac`]) the built-in
//! netdev drives, call for call:
//!
//! - **netdev** — `narf_netif_register_with_context` (the bridge names it
//!   `wlan%d` because the device has a wireless session); TX frames arrive
//!   in [`tx_callback`], RX goes out through `narf_netif_rx`;
//! - **wiphy** — `REGISTER_WIPHY` binds the shell to that netdev and
//!   advertises the radio's bands, HT/VHT/HE, ciphers and the in-driver SME
//!   (PSK and SAE offload);
//! - **control** — the host's `SCAN_REQUEST` / `CONNECT` / `DISCONNECT`
//!   events run [`ModuleNetdev::scan`] / [`ModuleNetdev::associate_kernel`]
//!   / [`ModuleNetdev::disassociate`] (the in-driver supplicant does
//!   WPA2-PSK and WPA3-SAE), whose outcomes go back as `SCAN_RESULT` /
//!   `SCAN_DONE` / `CONNECT_RESULT` / `DISCONNECTED`;
//! - **link** — carrier follows those reports; a link loss the MAC detects
//!   in its poll is reported as `DISCONNECTED`.
//!
//! Not carried yet (built-in only): firmware crash recovery, AP/P2P/
//! monitor, WoW/system PM, power save control, checksum offload and the
//! userspace SME. A firmware crash marks the radio down and says so.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use narf_wireless::scan::BssSecurity;
use narf_wireless::{AssociateRequest, BssInfo, ScanRequest, SecurityConfig, WirelessError};

use super::ce::CeIrq as _;
use super::mac::{Disconnect, Mac};
use super::mac_frame::{self as frame, freq_band, Band};
use super::mac_reg::chan_flag;
use super::platform::{self, Console, IrqSafeSpinLock, Mutex};
use super::runtime::{Port, ScanLease, Shared};

type Io = super::core::Bar0;
type Irq = super::ce::MsiCeIrq;
type Q = super::pci::Wlfw;
/// The PCI runtime.
pub type PciShared = Shared<Io, Irq, Q>;
/// The PCI MAC.
pub type PciMac = Mac<Port<Io, Irq, Q>, Port<Io, Irq, Q>>;

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
}

/// Frames the TX pump hands the TXQs per runtime step (`NAPI_POLL_WEIGHT`).
const TX_BATCH: usize = 64;
/// TX frames queued between the stack and the pump.
const TX_QUEUE_MAX: usize = 512;
const ENOBUFS: i32 = -105;

/// The station netdev of the module build.
#[allow(missing_debug_implementations)]
pub struct ModuleNetdev {
    mac_addr: [u8; 6],
    vdev_id: u32,
    ifindex: u32,
    session: u64,
    shared: Arc<PciShared>,
    mac: Mutex<PciMac>,
    /// bit 63 = associated, low 48 bits = BSSID (LE).
    bssid: AtomicU64,
    /// Centre frequency of the association.
    frequency: AtomicU32,
    up: AtomicBool,
    /// Stop servicing: the firmware crashed and the module cannot recover.
    dead: AtomicBool,
    tx: IrqSafeSpinLock<VecDeque<Vec<u8>>>,
    /// The last scan's networks, for a `CONNECT` without a BSSID.
    last_scan: IrqSafeSpinLock<Vec<BssInfo>>,
}

/// The one radio (WCN6855 has one pdev). Callbacks find it here.
static NETDEV: IrqSafeSpinLock<Option<Arc<ModuleNetdev>>> = IrqSafeSpinLock::new(None);

fn netdev() -> Option<Arc<ModuleNetdev>> {
    NETDEV.lock().clone()
}

fn log(args: core::fmt::Arguments<'_>) {
    let _ = writeln!(Console, "  ath11k.ko: {}", args);
}

impl ModuleNetdev {
    fn link_up(&self) -> bool {
        self.up.load(Ordering::Acquire)
    }

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

    /// Carrier on with the association (`ieee80211_set_associated`).
    fn link_up_to(&self, bssid: [u8; 6], frequency_mhz: u32) {
        let mut packed = 1u64 << 63;
        for (i, byte) in bssid.iter().enumerate() {
            packed |= (*byte as u64) << (8 * i);
        }
        self.bssid.store(packed, Ordering::Release);
        self.frequency.store(frequency_mhz, Ordering::Release);
        self.up.store(true, Ordering::Release);
        let _ = self.report(
            wifi::OP_CONNECT_RESULT,
            &encode_connect_result(0, bssid, frequency_mhz),
        );
        platform::diag::set_wifi_stage(platform::diag::WifiStage::Connected);
    }

    /// Carrier off (`ieee80211_set_disassoc`), reporting why.
    fn link_down(&self, why: Option<Disconnect>) {
        let was = self.up.swap(false, Ordering::AcqRel);
        self.bssid.store(0, Ordering::Release);
        self.frequency.store(0, Ordering::Release);
        self.shared.clear_operating_channel(self.vdev_id);
        if was {
            let (reason, local) = why.map_or((frame::WLAN_REASON_DEAUTH_LEAVING, true), |d| {
                (d.reason, !d.from_ap)
            });
            let _ = self.report(wifi::OP_DISCONNECTED, &encode_disconnected(reason, local));
        }
    }

    /// `ieee80211_do_open` for the station: start the hardware when this is
    /// the first vdev, then add the station interface.
    async fn ensure_open(&self, m: &mut PciMac) -> bool {
        if m.vif().is_some() {
            return true;
        }
        if let Some(((tx, rx), _generation)) = self.shared.antenna_config() {
            m.configure_antenna(tx, rx);
        }
        let (rts_threshold, _generation) = self.shared.rts_config();
        m.configure_rts_threshold(rts_threshold);
        let started_here = self.shared.acquire_radio_mac();
        if started_here {
            if let Err(e) = m.start().await {
                self.shared.release_radio_mac();
                e.report("ath11k.ko start");
                return false;
            }
            if let Some(table) = self.shared.bios_sar_table() {
                if let Err(e) = m.set_bios_sar_table(&table).await {
                    m.stop().await;
                    self.shared.release_radio_mac();
                    e.report("ath11k.ko BIOS SAR");
                    return false;
                }
            }
        } else {
            m.adopt_shared_start();
        }
        if let Err(e) = m.add_interface().await {
            if started_here {
                m.stop().await;
            } else {
                m.leave_shared_start();
            }
            self.shared.release_radio_mac();
            e.report("ath11k.ko add interface");
            return false;
        }
        true
    }

    /// One scan (the built-in netdev's `scan`): the radio-wide scan lease,
    /// then the MAC's scan.
    pub async fn scan(&self, req: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        if self.shared.is_dead() || self.dead.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        let mut lease =
            ScanLease::acquire(self.shared.clone(), self.vdev_id).ok_or(WirelessError::Busy)?;
        let result = {
            let mut m = self.mac.lock().await;
            if !self.ensure_open(&mut m).await {
                Err(WirelessError::HardwareError)
            } else {
                m.scan(&req).await
            }
        };
        lease.complete();
        if let Ok(list) = &result {
            *self.last_scan.lock() = list.clone();
        }
        result
    }

    /// Associate with the in-driver SME (the built-in `associate_from`
    /// with a kernel origin): WPA2-PSK from a PMK or WPA3-SAE from a
    /// password run inside the driver.
    pub async fn associate_kernel(&self, req: AssociateRequest) -> Result<(), WirelessError> {
        if matches!(req.security, SecurityConfig::External(_)) {
            return Err(WirelessError::NotSupported);
        }
        if self.shared.is_dead() || self.dead.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        let mut m = self.mac.lock().await;
        if !self.ensure_open(&mut m).await {
            return Err(WirelessError::HardwareError);
        }
        let Some(previous_frequency) = self
            .shared
            .reserve_operating_channel(self.vdev_id, req.frequency_mhz)
        else {
            return Err(WirelessError::Busy);
        };
        let result = m.associate(&req).await;
        let bssid = m.connected_bssid();
        drop(m);
        if let Err(error) = result {
            self.shared
                .restore_operating_channel(self.vdev_id, previous_frequency);
            return Err(error);
        }
        match bssid {
            Some(b) => {
                self.link_up_to(b, req.frequency_mhz);
                Ok(())
            }
            None => {
                self.shared
                    .restore_operating_channel(self.vdev_id, previous_frequency);
                Err(WirelessError::Denied)
            }
        }
    }

    /// Disconnect (the built-in netdev's `disassociate`).
    pub async fn disassociate(&self) -> Result<(), WirelessError> {
        let mut m = self.mac.lock().await;
        if m.link().is_some() {
            self.shared.flush_queues_for(self.vdev_id, true).await;
        }
        let r = m.disassociate().await;
        let why = m.take_disconnect();
        drop(m);
        self.link_down(why);
        r
    }

    /// A `CONNECT` that left the BSS to the driver (all-zero BSSID): the
    /// strongest matching network of the last scan
    /// (`cfg80211_get_bss` in `cfg80211_sme_get_conn_ies`).
    fn resolve_bss(&self, mut req: AssociateRequest) -> Option<AssociateRequest> {
        if req.bssid != [0; 6] && req.frequency_mhz != 0 {
            return Some(req);
        }
        let wpa2 = !matches!(req.security, SecurityConfig::Open);
        let scan = self.last_scan.lock();
        let bss = if req.bssid != [0; 6] {
            scan.iter()
                .find(|b| b.bssid == req.bssid)
                .map(|b| (b.bssid, b.frequency_mhz))
        } else if matches!(req.security, SecurityConfig::Wpa3 { .. }) {
            scan.iter()
                .filter(|b| b.ssid == req.ssid && matches!(b.security, BssSecurity::Wpa3))
                .max_by_key(|b| b.rssi)
                .map(|b| (b.bssid, b.frequency_mhz))
        } else {
            super::autoconnect::pick(&scan, &req.ssid, wpa2).map(|b| (b.bssid, b.frequency_mhz))
        }?;
        req.bssid = bss.0;
        req.frequency_mhz = bss.1;
        req.channel = frame::freq_to_channel(bss.1);
        Some(req)
    }

    /// Deliver received frames to the stack (`narf_netif_rx`).
    fn deliver(&self, frames: Vec<(Vec<u8>, bool)>) -> usize {
        let n = frames.len();
        for (mut f, _csum_ok) in frames {
            // SAFETY: `f` names `len` bytes the call may rewrite in place.
            let _ = unsafe {
                ffi::narf_netif_rx(platform::device(), self.ifindex, f.as_mut_ptr(), f.len())
            };
        }
        n
    }

    /// One pass of the runtime loop (the built-in `service_once`, station
    /// subset): RX delivery, firmware notices, MAC housekeeping, link loss.
    pub async fn service_once(&self) -> usize {
        if self.shared.take_scan_cancel(self.vdev_id) {
            let mut m = self.mac.lock().await;
            m.cancel_scan().await;
            drop(m);
            self.shared.release_scan(self.vdev_id);
        }
        let frames = self.shared.take_rx_for(self.vdev_id).await;
        let n = self.deliver(frames);
        if let Some(notice) = self.shared.take_fw_notice().await {
            log(format_args!(
                "firmware notice {:?}: crash recovery is not carried by the module build; \
                 the radio is down until the module is reloaded",
                notice
            ));
            platform::diag::note_wifi_crash();
            self.dead.store(true, Ordering::Release);
            self.link_down(None);
            return n;
        }
        if let Some(mut m) = self.mac.try_lock() {
            let loss = m.poll().await;
            let linked = m.connected_bssid();
            let scan_idle = m.scan_state() == super::mac::ScanState::Idle;
            let why = if linked.is_none() {
                m.take_disconnect()
            } else {
                None
            };
            drop(m);
            if loss.is_some() {
                self.shared.lock().await.purge_txqs_for(self.vdev_id);
            }
            if scan_idle && self.shared.owns_scan(self.vdev_id) {
                self.shared.release_scan(self.vdev_id);
            }
            if linked.is_none() && self.link_up() {
                self.link_down(why);
            }
        }
        n
    }

    /// The runtime loop task.
    async fn run(self: Arc<Self>) {
        loop {
            self.service_once().await;
            if self.shared.is_dead() || self.dead.load(Ordering::Acquire) {
                return;
            }
            self.shared.irq.wait(self.shared.slice_ms).await;
        }
    }

    /// The TX pump: frames the stack queued → the runtime's per-AC TXQs.
    async fn tx_pump(self: Arc<Self>) {
        loop {
            if self.dead.load(Ordering::Acquire) {
                return;
            }
            let batch: Vec<(Vec<u8>, bool, bool)> = {
                let mut q = self.tx.lock();
                let n = q.len().min(TX_BATCH);
                q.drain(..n).map(|f| (f, false, false)).collect()
            };
            if batch.is_empty() {
                platform::time::SleepUntil::new(platform::time::Deadline::after_ms(1).as_instant())
                    .await;
                continue;
            }
            if !self.link_up() {
                continue;
            }
            let _ = self
                .shared
                .tx_frames_with_flags_for(self.vdev_id, batch)
                .await;
        }
    }
}

#[async_trait::async_trait]
impl super::autoconnect::KernelConnect for ModuleNetdev {
    fn name(&self) -> &str {
        "wlan"
    }
    fn connected_bssid(&self) -> Option<[u8; 6]> {
        self.connected()
    }
    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.mac
            .try_lock()?
            .bss_table()
            .iter()
            .find(|b| b.bssid == bssid)
            .map(|b| b.ies.clone())
    }
    async fn scan(&self, req: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        ModuleNetdev::scan(self, req).await
    }
    async fn associate_kernel(&self, req: AssociateRequest) -> Result<(), WirelessError> {
        ModuleNetdev::associate_kernel(self, req).await
    }
}

/// Netif TX: the stack hands one Ethernet frame (borrowed for this call).
extern "C" fn tx_callback(_dev: u64, frame: *const u8, len: usize) -> i32 {
    let Some(dev) = netdev() else {
        return -19;
    };
    if frame.is_null() || len < 14 || !dev.link_up() {
        return ENOBUFS;
    }
    // SAFETY: the bridge lends `len` readable bytes for the call.
    let bytes = unsafe { core::slice::from_raw_parts(frame, len) }.to_vec();
    let mut q = dev.tx.lock();
    if q.len() >= TX_QUEUE_MAX {
        return ENOBUFS;
    }
    q.push_back(bytes);
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
                    Some(req) => dev.associate_kernel(req).await,
                    None => Err(WirelessError::InvalidArgs),
                };
                if let Err(e) = result {
                    log(format_args!("connect failed: {:?}", e));
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
                    &encode_disconnected(frame::WLAN_REASON_DEAUTH_LEAVING, true),
                );
            });
            0
        }
        // The MAC's scan has no cancellation hook here; the result of an
        // aborted scan is simply discarded by the host.
        wifi::EVENT_SCAN_ABORT => 0,
        _ => -95,
    }
}

async fn scan_and_report(dev: &ModuleNetdev, req: ScanRequest) {
    let status = match dev.scan(req).await {
        Ok(results) => {
            let table: Vec<(BssInfo, Vec<u8>)> = {
                let ies = |b: [u8; 6]| {
                    super::autoconnect::KernelConnect::scan_information_elements(dev, b)
                };
                results
                    .into_iter()
                    .map(|b| {
                        let i = ies(b.bssid).unwrap_or_default();
                        (b, i)
                    })
                    .collect()
            };
            for (bss, ies) in table {
                let _ = dev.report(wifi::OP_SCAN_RESULT, &encode_scan_result(&bss, &ies));
            }
            0i32
        }
        Err(WirelessError::Busy) => -16,
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
        channel: frame::freq_to_channel(frequency_mhz),
        security,
        ie,
    })
}

/// `REGISTER_WIPHY` from the MAC's channel table and capabilities (the
/// built-in `RadioInfo::from_mac`, station subset).
fn encode_register_wiphy(ifindex: u32, mac_addr: [u8; 6], m: &PciMac) -> Vec<u8> {
    let (mut b2, mut b5, mut b6) = (Vec::new(), Vec::new(), Vec::new());
    for c in m.wiphy().iter() {
        if c.flags & chan_flag::DISABLED != 0 {
            continue;
        }
        let ch = frame::freq_to_channel(c.center_freq);
        if ch == 0 || ch > 233 {
            continue;
        }
        let list = match freq_band(c.center_freq) {
            Band::Ghz2 => &mut b2,
            Band::Ghz5 => &mut b5,
            Band::Ghz6 => &mut b6,
        };
        if list.len() < 64 && !list.contains(&(ch as u8)) {
            list.push(ch as u8);
        }
    }
    let own = m.own_caps();
    let mut hw = 0u8;
    if own.ht_2g.ht_supported || own.ht_5g.ht_supported {
        hw |= 1;
    }
    if own.vht_5g.vht_supported {
        hw |= 2;
    }
    if m.own_he(Band::Ghz2).is_some()
        || m.own_he(Band::Ghz5).is_some()
        || m.own_he(Band::Ghz6).is_some()
    {
        hw |= 4;
    }
    // `ath11k_mac_register`'s suites the host recognises (TKIP left out:
    // the host advertises at most eight, and TKIP is the one to drop).
    let ciphers = [
        narf_wireless::CIPHER_SUITE_CCMP,
        narf_wireless::CIPHER_SUITE_GCMP,
        narf_wireless::CIPHER_SUITE_CCMP_256,
        narf_wireless::CIPHER_SUITE_GCMP_256,
        narf_wireless::CIPHER_SUITE_AES_CMAC,
        narf_wireless::CIPHER_SUITE_BIP_CMAC_256,
        narf_wireless::CIPHER_SUITE_BIP_GMAC_128,
        narf_wireless::CIPHER_SUITE_BIP_GMAC_256,
    ];
    let bands: Vec<(u32, &Vec<u8>)> = [(2412u32, &b2), (5180, &b5), (5955, &b6)]
        .into_iter()
        .filter(|(_, list)| !list.is_empty())
        .collect();
    let mut out = Vec::new();
    out.extend_from_slice(&ifindex.to_le_bytes());
    out.extend_from_slice(&mac_addr);
    out.extend_from_slice(&1u32.to_le_bytes()); // STATION
    out.push(hw);
    out.push(ciphers.len() as u8);
    out.push(bands.len() as u8);
    out.push(wifi::FLAG_PSK_OFFLOAD | wifi::FLAG_SAE_OFFLOAD | wifi::FLAG_REPORTS_DISCONNECT);
    out.push(16); // max scan SSIDs (the built-in netdev's)
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
    out
}

/// Publish the PCI radio's netdev and wiphy (the module build's
/// `iface::register_pci`): session, netdev, wiphy, then the runtime loop,
/// the TX pump and, if `ath11k.ssid=` / `ath11k.scan=` were given, the
/// autoconnect. Returns the name used in logs.
pub fn register_pci_module(
    shared: Arc<PciShared>,
    mac: PciMac,
    mac_addr: [u8; 6],
    vdev_id: u32,
) -> String {
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
        return String::from("wlan?");
    }
    let mut ifindex = 0u32;
    // SAFETY: `mac_addr` names six readable bytes; `tx_callback` is a valid
    // extern "C" fn in this image; `ifindex` is a live local.
    let rc = unsafe {
        ffi::narf_netif_register_with_context(
            dev_token,
            mac_addr.as_ptr(),
            tx_callback as usize,
            &mut ifindex,
        )
    };
    if rc != 0 {
        log(format_args!("netdev registration refused ({rc})"));
        return String::from("wlan?");
    }
    let wiphy = encode_register_wiphy(ifindex, mac_addr, &mac);
    let dev = Arc::new(ModuleNetdev {
        mac_addr,
        vdev_id,
        ifindex,
        session,
        shared,
        mac: Mutex::new(mac),
        bssid: AtomicU64::new(0),
        frequency: AtomicU32::new(0),
        up: AtomicBool::new(false),
        dead: AtomicBool::new(false),
        tx: IrqSafeSpinLock::new(VecDeque::new()),
        last_scan: IrqSafeSpinLock::new(Vec::new()),
    });
    let rc = dev.report(wifi::OP_REGISTER_WIPHY, &wiphy);
    if rc != 0 {
        log(format_args!("wiphy registration refused ({rc})"));
    }
    *NETDEV.lock() = Some(dev.clone());
    let d = dev.clone();
    platform::spawn(async move {
        // Like `ip link set wlan0 up`: open the station now (the module has
        // no IFF_UP event), then service the radio.
        {
            let mut m = d.mac.lock().await;
            let _ = d.ensure_open(&mut m).await;
        }
        d.run().await;
    });
    platform::spawn(dev.clone().tx_pump());
    match super::autoconnect::parse_params() {
        Ok(Some(cfg)) => {
            log(format_args!("autoconnect {:?}", cfg));
            platform::spawn(super::autoconnect::run(dev, cfg));
        }
        Ok(None) => {}
        Err(e) => log(format_args!("ignoring ath11k.* parameters: {:?}", e)),
    }
    alloc::format!("wlan (ifindex {ifindex})")
}
