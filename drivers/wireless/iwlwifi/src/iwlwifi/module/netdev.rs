//! The module build's netdev and wiphy (`iwlwifi.ko`).
//!
//! Built in, `device::Device` is the MLD station: a `WirelessNetIface` with
//! frame rings, scan, association, the in-driver WPA2/WPA3 supplicant, AP and
//! P2P roles, scheduled scan and system PM. A module reaches the network stack
//! only through the netif bridge and the `WIFI` family host
//! (`wireless/src/module_host.rs`, version 2), and this stage carries the
//! radio up to, not including, any emission:
//!
//! - **netdev** — `narf_netif_register_with_context` (named `wlan%d`
//!   because the device has a wireless session). Carrier never comes up, so
//!   [`tx_callback`] refuses frames and nothing is received.
//! - **wiphy** — `REGISTER_WIPHY` advertises the NVM's channels (2.4/5 GHz,
//!   and 6 GHz when the firmware reports band-in-RX and HE), HT/VHT/HE/EHT
//!   from the NVM SKU, CCMP, and no SME offload.
//! - **scan** — `SCAN_REQUEST` runs the firmware's passive scan (the built-in
//!   `Device::scan` job without its regulatory-authorized active branch,
//!   which is also what the built-in runs while no signed regulatory policy
//!   is loaded): `SCAN_REQ` per band phase, beacons/probe responses from the
//!   RX ring parsed by the driver's MLME into `SCAN_RESULT`s with their IEs,
//!   `SCAN_COMPLETE` into `SCAN_DONE`. A failed scan restarts the firmware
//!   before the next one, as built in (`Device::recover`).
//! - **connect** — refused: `CONNECT_RESULT` with "unspecified failure".
//!   Association and the data path need the signed regulatory database
//!   (`narf_wireless::reg::db`) and the ACPI/SMBIOS platform power inputs
//!   (`mld_policy`, `mld_power`) before any station TX, and neither has a
//!   KABI.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_wireless::scan::{BssSecurity, ColocatedAp};
use narf_wireless::{BssInfo, ScanRequest, WirelessError};

use super::super::native_band::{Band, Channel};
use super::super::runtime::Hardware;
use super::super::{boot_context, ht_vht, mld_start, mlme, parse_ucode, scan_api, station_api};
use super::kernel::narf_console::Writer;
use super::kernel::narf_lib::mutex::Mutex;
use super::kernel::narf_lib::sync::IrqSafeSpinLock;
use super::kernel::narf_time;

/// KABI exports the netdev glue calls.
mod ffi {
    unsafe extern "C" {
        pub fn narf_netif_register_with_context(
            dev: u64,
            mac: *const u8,
            tx_callback: usize,
            out_ifindex: *mut u32,
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
    /// `WirelessModes::STATION`.
    pub const MODE_STATION: u32 = 1;
    /// IEEE 802.11 status: unspecified failure.
    pub const STATUS_UNSPECIFIED_FAILURE: u16 = 1;
    /// IEEE 802.11 reason: deauthenticated because the station is leaving.
    pub const REASON_DEAUTH_LEAVING: u16 = 3;
    /// Host limits (`module_host.rs`).
    pub const MAX_SCAN_SSIDS: u8 = 16;
    pub const MAX_CHANNELS_PER_BAND: usize = 64;
}

const ENOBUFS: i32 = -105;
const ECANCELED: i32 = -125;
const EBUSY: i32 = -16;
const EIO: i32 = -5;
const EINVAL: i32 = -22;
const ENODEV: i32 = -19;
const EOPNOTSUPP: i32 = -95;
/// The built-in scan job's bound (`Device::scan`).
const SCAN_TIMEOUT_MS: u64 = 15_000;
/// Results kept per scan (the built-in's, and the host's).
const SCAN_RESULTS_MAX: usize = 256;

/// The executable and the PNVM the transport booted, retained for a restart
/// (`Device::recover`).
pub(crate) struct Firmware {
    pub executable: Vec<u8>,
    pub pnvm: Option<Vec<u8>>,
}

struct State {
    hardware: Hardware,
    /// The last firmware job failed: restart before the next one.
    needs_reset: bool,
}

/// One bound radio (module build).
struct Radio {
    mac: [u8; 6],
    ifindex: u32,
    session: u64,
    channels: Vec<u8>,
    six_channels: Vec<Channel>,
    tx_chains: u32,
    rx_chains: u32,
    phy: ht_vht::Local,
    firmware: Firmware,
    state: Mutex<State>,
    /// A restart failed: the radio stays down until the module is reloaded.
    dead: AtomicBool,
    /// The host aborted the running scan.
    abort: AtomicBool,
}

/// The radio callbacks find.
static RADIO: IrqSafeSpinLock<Option<Arc<Radio>>> = IrqSafeSpinLock::new(None);

fn radio() -> Option<Arc<Radio>> {
    RADIO.lock().clone()
}

fn log(args: core::fmt::Arguments<'_>) {
    let _ = writeln!(Writer, "  iwlwifi.ko: {}", args);
}

/// Why a scan stopped early.
enum ScanError {
    Wireless(WirelessError),
    Aborted,
}

impl From<WirelessError> for ScanError {
    fn from(error: WirelessError) -> Self {
        ScanError::Wireless(error)
    }
}

impl Radio {
    /// Submit a report to the family host and collect its status (every v2
    /// report completes at submit).
    fn report(&self, opcode: u32, request: &[u8]) -> i32 {
        let mut op = 0u64;
        // SAFETY: `request` names `len` readable bytes; `op` is a live local.
        let rc = unsafe {
            ffi::narf_wireless_submit(
                super::device(),
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
                super::device(),
                self.session,
                op,
                reply.as_mut_ptr(),
                reply.len(),
                &mut len,
            )
        }
    }

    /// `Device::recover`: restart the firmware from the retained images and
    /// re-run the configuration; the MAC, chains, channels and PHY must come
    /// back unchanged.
    async fn recover(&self, state: &mut State) -> Result<(), WirelessError> {
        let mut parsed =
            parse_ucode(&self.firmware.executable).map_err(|_| WirelessError::HardwareError)?;
        parsed.api.pnvm = self.firmware.pnvm.as_deref();
        let mac = state
            .hardware
            .restart(&parsed)
            .await
            .map_err(|_| WirelessError::HardwareError)?;
        if mac != self.mac {
            state.hardware.fail();
            return Err(WirelessError::HardwareError);
        }
        let nvm = mld_start::configure(&mut state.hardware, mac)
            .await
            .map_err(|_| WirelessError::HardwareError)?;
        if nvm.tx_chains != self.tx_chains
            || nvm.rx_chains != self.rx_chains
            || nvm.channels != self.channels
            || nvm.six_channels != self.six_channels
            || nvm.phy != self.phy
        {
            state.hardware.fail();
            return Err(WirelessError::HardwareError);
        }
        state.needs_reset = false;
        Ok(())
    }

    /// The channels a request selects (the built-in `Device::scan` rules):
    /// frequencies are authoritative, numeric-only selectors keep the legacy
    /// 2.4/5 GHz meaning, and an empty request scans every NVM channel.
    fn select_channels(&self, request: &ScanRequest) -> Result<Vec<Channel>, WirelessError> {
        let mut supported: Vec<Channel> = self
            .channels
            .iter()
            .filter_map(|&ch| Channel::legacy(ch))
            .collect();
        supported.extend_from_slice(&self.six_channels);
        let mut channels = Vec::new();
        if !request.frequencies_mhz.is_empty() {
            for &frequency in &request.frequencies_mhz {
                let channel = supported
                    .iter()
                    .find(|ch| ch.frequency() == frequency)
                    .copied()
                    .ok_or(WirelessError::InvalidArgs)?;
                if !channels.contains(&channel) {
                    channels.push(channel);
                }
            }
        } else if request.channels.is_empty() {
            channels = supported;
        } else {
            for &number in &request.channels {
                let number = u8::try_from(number).map_err(|_| WirelessError::InvalidArgs)?;
                let channel = Channel::legacy(number)
                    .filter(|ch| supported.contains(ch))
                    .ok_or(WirelessError::InvalidArgs)?;
                if !channels.contains(&channel) {
                    channels.push(channel);
                }
            }
        }
        if channels.is_empty() {
            return Err(WirelessError::InvalidArgs);
        }
        Ok(channels)
    }

    /// One passive scan: the legacy bands, then the 6 GHz channels the RNR
    /// plan selects. Results carry their information elements.
    async fn scan(&self, mut request: ScanRequest) -> Result<Vec<(BssInfo, Vec<u8>)>, ScanError> {
        if self.dead.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError.into());
        }
        if request.ssids.len() > 20 || request.ssids.iter().any(|ssid| ssid.len() > 32) {
            return Err(WirelessError::InvalidArgs.into());
        }
        let channels = self.select_channels(&request)?;
        request.frequencies_mhz = channels.iter().map(|ch| ch.frequency()).collect();
        let legacy: Vec<Channel> = channels
            .iter()
            .copied()
            .filter(|ch| ch.band != Band::Six)
            .collect();
        let six: Vec<Channel> = channels
            .iter()
            .copied()
            .filter(|ch| ch.band == Band::Six)
            .collect();
        let mut state = self.state.try_lock().ok_or(WirelessError::Busy)?;
        if state.needs_reset || state.hardware.is_failed() {
            if let Err(error) = self.recover(&mut state).await {
                self.dead.store(true, Ordering::Release);
                log(format_args!(
                    "firmware restart failed; the radio is down until the module is reloaded"
                ));
                return Err(error.into());
            }
        }
        self.abort.store(false, Ordering::Release);
        state.needs_reset = true;
        let outcome = self
            .scan_jobs(&mut state.hardware, &request, &legacy, &six)
            .await;
        state.needs_reset = outcome.is_err();
        if outcome.is_err() {
            state.hardware.fail();
        }
        outcome
    }

    async fn scan_jobs(
        &self,
        hw: &mut Hardware,
        request: &ScanRequest,
        legacy: &[Channel],
        six: &[Channel],
    ) -> Result<Vec<(BssInfo, Vec<u8>)>, ScanError> {
        // Only one scan runs at a time; firmware scan slot zero.
        let uid = 0u32;
        let version = hw.version(1, 0xd).ok_or(WirelessError::NotSupported)?.0;
        let mut result: Vec<(BssInfo, Vec<u8>)> = Vec::new();
        let mut colocated: Vec<ColocatedAp> = Vec::new();
        for phase in 0..2 {
            let channels: Vec<Channel> = if phase == 1 {
                let plan = narf_wireless::scan::plan_6ghz_scan(request, &colocated, None);
                six.iter()
                    .copied()
                    .filter(|ch| plan.frequencies_mhz.contains(&ch.frequency()))
                    .collect()
            } else {
                legacy.to_vec()
            };
            if channels.is_empty() {
                continue;
            }
            let mut body = scan_api::passive_channels(version, uid, &channels)
                .map_err(|_| WirelessError::NotSupported)?;
            if channels[0].band == Band::Six && hw.scan_fixed_antenna_supported() {
                body[17] = 1 << 2; // MLD, or MVM's actual capability111.
            }
            hw.notifications
                .retain(|p| !(p.header.group_id == 0 && matches!(p.header.cmd, 0xf | 0xc1)));
            hw.command(1, 0xd, &body)
                .await
                .map_err(|_| WirelessError::HardwareError)?;
            let deadline = narf_time::Deadline::after_ms(SCAN_TIMEOUT_MS);
            'native_job: loop {
                let activity = hw.activity();
                hw.poll().map_err(|_| WirelessError::HardwareError)?;
                while let Some(packet) = hw.notifications.pop_front() {
                    if packet.header.group_id != 0 {
                        continue;
                    }
                    if packet.header.cmd == 0xf {
                        if packet.payload.len() != 16 {
                            return Err(WirelessError::HardwareError.into());
                        }
                        if packet.payload[..4] != uid.to_le_bytes() {
                            continue;
                        }
                        if packet.payload[6] != 1 {
                            return Err(WirelessError::HardwareError.into());
                        }
                        break 'native_job;
                    }
                    if packet.receive_queue != 0 || packet.header.cmd != 0xc1 {
                        continue;
                    }
                    let Some(mpdu) = scan_api::mpdu(&packet.payload) else {
                        continue;
                    };
                    let Some(channel) =
                        Channel::received(mpdu.channel, mpdu.raw_band, hw.band_in_rx_supported())
                            .filter(|channel| channels.contains(channel))
                    else {
                        continue;
                    };
                    if mpdu.frame.len() < 36 || !matches!(mpdu.frame[0], 0x80 | 0x50) {
                        continue;
                    }
                    let mut bssid = [0u8; 6];
                    bssid.copy_from_slice(&mpdu.frame[16..22]);
                    let Some(body) = mpdu.body(24, 0) else {
                        continue;
                    };
                    let Some(beacon) = mlme::parse_beacon_to_bss(bssid, body) else {
                        continue;
                    };
                    if phase == 0 && request.colocated_6ghz {
                        for ap in narf_wireless::scan::parse_colocated_aps(&body[12..]) {
                            if colocated.len() < 256
                                && !colocated.iter().any(|old| {
                                    old.bssid == ap.bssid && old.frequency_mhz == ap.frequency_mhz
                                })
                            {
                                colocated.push(ap);
                            }
                        }
                    }
                    if !request.ssids.is_empty()
                        && !request.ssids.iter().any(Vec::is_empty)
                        && !request.ssids.contains(&beacon.ssid)
                    {
                        continue;
                    }
                    let security = if channel.band == Band::Six
                        && beacon
                            .rsn_ie_body
                            .as_deref()
                            .and_then(narf_wireless::rsn::RsnIe::decode_body)
                            .is_some_and(|rsn| {
                                rsn.akms.iter().any(|suite| {
                                    suite.oui == narf_wireless::rsn::RSN_OUI
                                        && matches!(suite.suite_type, 8 | 24)
                                })
                            }) {
                        BssSecurity::Wpa3
                    } else if beacon.rsn_ie_body.is_some() {
                        BssSecurity::Wpa2
                    } else if u16::from_le_bytes([mpdu.frame[34], mpdu.frame[35]]) & 0x10 != 0 {
                        BssSecurity::Wep
                    } else {
                        BssSecurity::Open
                    };
                    let bss = BssInfo {
                        bssid,
                        ssid: beacon.ssid,
                        frequency_mhz: channel.frequency(),
                        channel: u32::from(mpdu.channel),
                        rssi: mpdu.rssi,
                        security,
                    };
                    let ies = body.get(12..).unwrap_or_default().to_vec();
                    if let Some(old) = result.iter_mut().find(|(entry, _)| {
                        entry.bssid == bssid && entry.frequency_mhz == channel.frequency()
                    }) {
                        *old = (bss, ies);
                    } else if result.len() < SCAN_RESULTS_MAX {
                        result.push((bss, ies));
                    }
                }
                let aborted = self.abort.swap(false, Ordering::AcqRel);
                if aborted || deadline.expired() {
                    let mut abort = [0; 8];
                    boot_context::put32(&mut abort, 0, uid);
                    hw.command(1, 0xe, &abort)
                        .await
                        .map_err(|_| WirelessError::HardwareError)?;
                    hw.wait_notification(0, 0xf, 2000)
                        .await
                        .map_err(|_| WirelessError::HardwareError)?;
                    return Err(if aborted {
                        ScanError::Aborted
                    } else {
                        WirelessError::Timeout.into()
                    });
                }
                activity.await;
            }
        }
        Ok(result)
    }

    /// The idle service: drain the RX ring so firmware notifications nothing
    /// waits for cannot overflow the transport's bounded queue. Scans drain
    /// it themselves while they hold the radio.
    async fn service(self: Arc<Self>) {
        loop {
            if self.dead.load(Ordering::Acquire) {
                return;
            }
            let activity = match self.state.try_lock() {
                Some(mut state) => {
                    let activity = state.hardware.activity();
                    if !state.needs_reset && !state.hardware.is_failed() {
                        if state.hardware.poll().is_err() {
                            log(format_args!(
                                "firmware/transport error; restarting before the next scan"
                            ));
                            state.needs_reset = true;
                        }
                        state.hardware.notifications.clear();
                    }
                    Some(activity)
                }
                None => None,
            };
            match activity {
                Some(activity) => activity.await,
                None => narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(10_000_000)).await,
            }
        }
    }
}

/// Netif TX: carrier is never up in this stage, so every frame is refused.
extern "C" fn tx_callback(_dev: u64, _frame: *const u8, _len: usize) -> i32 {
    ENOBUFS
}

/// Family-host events: queue the work on the executor and accept it; the
/// outcome is reported when it completes.
extern "C" fn event_callback(_dev: u64, event: u32, payload: *const u8, len: usize) -> i32 {
    let Some(radio) = radio() else {
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
            let _ = super::EXEC.spawn(async move { scan_and_report(&radio, request).await });
            0
        }
        wifi::EVENT_CONNECT => {
            let Some((bssid, frequency)) = decode_connect_target(&bytes) else {
                return EINVAL;
            };
            let _ = super::EXEC.spawn(async move {
                log(format_args!(
                    "connect refused: association is built-in only (no regulatory/platform \
                     power KABI for station TX)"
                ));
                let _ = radio.report(
                    wifi::OP_CONNECT_RESULT,
                    &encode_connect_result(wifi::STATUS_UNSPECIFIED_FAILURE, bssid, frequency),
                );
            });
            0
        }
        wifi::EVENT_DISCONNECT => {
            // Never associated; still complete the host's wait.
            let _ = super::EXEC.spawn(async move {
                let _ = radio.report(
                    wifi::OP_DISCONNECTED,
                    &encode_disconnected(wifi::REASON_DEAUTH_LEAVING, true),
                );
            });
            0
        }
        wifi::EVENT_SCAN_ABORT => {
            radio.abort.store(true, Ordering::Release);
            0
        }
        _ => EOPNOTSUPP,
    }
}

async fn scan_and_report(radio: &Radio, request: ScanRequest) {
    let status = match radio.scan(request).await {
        Ok(results) => {
            for (bss, ies) in results {
                let _ = radio.report(wifi::OP_SCAN_RESULT, &encode_scan_result(&bss, &ies));
            }
            0i32
        }
        Err(ScanError::Aborted) => ECANCELED,
        Err(ScanError::Wireless(WirelessError::Busy)) => EBUSY,
        Err(ScanError::Wireless(WirelessError::InvalidArgs)) => EINVAL,
        Err(ScanError::Wireless(WirelessError::NotSupported)) => EOPNOTSUPP,
        Err(ScanError::Wireless(_)) => EIO,
    };
    let _ = radio.report(wifi::OP_SCAN_DONE, &status.to_le_bytes());
}

// ── Wire records (`WIFI` v2, little-endian; `module_host.rs`) ─────────────

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

/// The BSSID and frequency of a `CONNECT` (enough to answer it).
fn decode_connect_target(b: &[u8]) -> Option<([u8; 6], u32)> {
    if b.len() < 20 {
        return None;
    }
    let mut bssid = [0u8; 6];
    bssid.copy_from_slice(&b[..6]);
    Some((bssid, u32::from_le_bytes([b[8], b[9], b[10], b[11]])))
}

/// `REGISTER_WIPHY` from the NVM (the built-in `get_wireless_info`, station
/// subset): station mode, the NVM's channels per band, HT/VHT/HE/EHT, CCMP
/// (the built-in station's suite) and no SME offload.
fn encode_register_wiphy(radio: &Radio) -> Vec<u8> {
    let (mut b2, mut b5, mut b6) = (Vec::new(), Vec::new(), Vec::new());
    for &ch in &radio.channels {
        let list = if ch <= 14 { &mut b2 } else { &mut b5 };
        if list.len() < wifi::MAX_CHANNELS_PER_BAND && !list.contains(&ch) {
            list.push(ch);
        }
    }
    for ch in &radio.six_channels {
        if b6.len() < wifi::MAX_CHANNELS_PER_BAND && !b6.contains(&ch.number) {
            b6.push(ch.number);
        }
    }
    let phy = radio.phy;
    let hw =
        u8::from(phy.ht) | u8::from(phy.vht) << 1 | u8::from(phy.he) << 2 | u8::from(phy.eht) << 3;
    let ciphers = [narf_wireless::CIPHER_SUITE_CCMP];
    let bands: Vec<(u32, &Vec<u8>)> = [(2412u32, &b2), (5180, &b5), (5955, &b6)]
        .into_iter()
        .filter(|(_, list)| !list.is_empty())
        .collect();
    let mut out = Vec::new();
    out.extend_from_slice(&radio.ifindex.to_le_bytes());
    out.extend_from_slice(&radio.mac);
    out.extend_from_slice(&wifi::MODE_STATION.to_le_bytes());
    out.push(hw);
    out.push(ciphers.len() as u8);
    out.push(bands.len() as u8);
    out.push(0); // no SME offload: association is not carried
    out.push(wifi::MAX_SCAN_SSIDS);
    out.push(0);
    // Passive scans send no probe request, so no probe IEs are taken.
    out.extend_from_slice(&0u16.to_le_bytes());
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

/// Publish the radio (the module build's `start_pumps` + registration):
/// session, netdev, wiphy, then the idle service.
pub(crate) fn publish(hardware: Hardware, mac: [u8; 6], nvm: station_api::Nvm, firmware: Firmware) {
    let dev = super::device();
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
        return;
    }
    let mut ifindex = 0u32;
    // SAFETY: `mac` names six readable bytes; `tx_callback` is a valid extern
    // "C" fn in this image; `ifindex` is a live local.
    let rc = unsafe {
        ffi::narf_netif_register_with_context(dev, mac.as_ptr(), tx_callback as usize, &mut ifindex)
    };
    if rc != 0 {
        log(format_args!("netdev registration refused ({rc})"));
        return;
    }
    let radio = Arc::new(Radio {
        mac,
        ifindex,
        session,
        channels: nvm.channels,
        six_channels: nvm.six_channels,
        tx_chains: nvm.tx_chains,
        rx_chains: nvm.rx_chains,
        phy: nvm.phy,
        firmware,
        state: Mutex::new(State {
            hardware,
            needs_reset: false,
        }),
        dead: AtomicBool::new(false),
        abort: AtomicBool::new(false),
    });
    let rc = radio.report(wifi::OP_REGISTER_WIPHY, &encode_register_wiphy(&radio));
    if rc != 0 {
        log(format_args!("wiphy registration refused ({rc})"));
    } else {
        log(format_args!(
            "wlan (ifindex {ifindex}) up: passive scan; association built-in only"
        ));
    }
    *RADIO.lock() = Some(radio.clone());
    let _ = super::EXEC.spawn(radio.service());
}
