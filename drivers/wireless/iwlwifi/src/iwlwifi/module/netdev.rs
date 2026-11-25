//! The module build's station netdev and wiphy (`iwlwifi.ko`).
//!
//! Built in, `device::Device` is the MLD station: a `WirelessNetIface` with
//! frame rings, scan, association, the in-driver WPA2/WPA3 supplicant, AP and
//! P2P roles, scheduled scan and system PM. A module reaches the network
//! stack only through the netif bridge and the `WIFI` family host
//! (`wireless/src/module_host.rs`, version 2), so this is `Device`'s station
//! subset over the same transport ([`Hardware`]) and the same station
//! ([`Connection`]), step for step:
//!
//! - **netdev** — `narf_netif_register_with_context` (the bridge names it
//!   `wlan%d` because the device has a wireless session); TX frames arrive in
//!   [`tx_callback`] and are queued to the station's data queues, RX goes out
//!   through `narf_netif_rx`.
//! - **wiphy** — `REGISTER_WIPHY` advertises the NVM's channels (6 GHz when
//!   the firmware reports band-in-RX and HE), HT/VHT/HE/EHT from the NVM SKU,
//!   CCMP, and the in-driver SME (`PSK_OFFLOAD | SAE_OFFLOAD |
//!   REPORTS_DISCONNECT`).
//! - **scan** — `SCAN_REQUEST` runs `Device::scan`'s firmware jobs: the
//!   legacy bands, then the 6 GHz RNR plan; active (probe requests at the
//!   regulatory TX ceiling) when the request asks for it and a regulatory
//!   domain is installed, passive otherwise. Results carry their IEs.
//! - **connect** — `CONNECT` runs `Device::associate_links` for one link:
//!   the policy transaction, `Connection::associate_links_in_domain` (open,
//!   WPA2-PSK from the PMK, or WPA3-SAE from the password, with 802.11w), the
//!   station policy fence, then carrier and `CONNECT_RESULT`. A `CONNECT`
//!   without a BSSID takes the strongest matching network of the last scan.
//! - **service** — `Device::step`'s station branch: RX through
//!   `receive_packet_checked` and the reorder timer, EAPOL rekeying and BA
//!   aggregation maintenance, TX publication with queue credit, beacon-loss
//!   and policy-loss detection (reported as `DISCONNECTED`), and a transport
//!   stop with firmware restart before the next operation on any failure.
//! - **disconnect** — `DISCONNECT` runs `Device::close_locked`.
//!
//! Not carried (built-in only): AP, P2P, monitor and virtual interfaces;
//! scheduled scan; MLO (the v2 `CONNECT` has no MLO request); roaming
//! between BSSes of one ESS; WoWLAN and system PM; CQM beacon-loss events;
//! checksum offload (the bridge carries no frame metadata); BIOS SAR/PPAG
//! (`module/platform_power.rs`).

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use narf_wireless::scan::{BssSecurity, ColocatedAp};
use narf_wireless::{BssInfo, ScanRequest, WirelessError};

use super::super::connection::{AuthMethod, Beacon, Connection};
use super::super::mld_policy::{self, Fence};
use super::super::native_band::{Band, Channel};
use super::super::progress::{PendingTx, Transmit};
use super::super::runtime::Hardware;
use super::super::{
    boot_context, ht_vht, mld_start, mlme, parse_ucode, scan_api, six_ghz_scan, station_api,
};
use super::kernel::narf_console::Writer;
use super::kernel::narf_lib::mutex::Mutex;
use super::kernel::narf_lib::sync::IrqSafeSpinLock;
use super::kernel::narf_time;
use super::regulatory;

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
    /// `WirelessModes::STATION`.
    pub const MODE_STATION: u32 = 1;
    /// IEEE 802.11 status: unspecified failure.
    pub const STATUS_UNSPECIFIED_FAILURE: u16 = 1;
    /// IEEE 802.11 reasons: unspecified; leaving.
    pub const REASON_UNSPECIFIED: u16 = 1;
    pub const REASON_DEAUTH_LEAVING: u16 = 3;
    /// Host limits (`module_host.rs`).
    pub const MAX_SCAN_SSIDS: u8 = 16;
    pub const MAX_SCAN_IE_LEN: u16 = 512;
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
/// Results and beacon records kept per scan (the built-in's, and the host's).
const SCAN_RESULTS_MAX: usize = 256;
/// Received frames handled per service step (`Device::step_owned`).
const RECEIVE_BUDGET: usize = 64;
/// Frames queued between the stack and the station.
const TX_QUEUE_MAX: usize = 512;
/// The built-in beacon-loss bound (`Device::step_owned`): 10 s.
const BEACON_LOSS_NS: u64 = 10_000_000_000;
/// How often the service re-reads the kernel's regulatory domain.
const REGULATORY_REFRESH_NS: u64 = 1_000_000_000;

/// The executable and the PNVM the transport booted, retained for a restart
/// (`Device::recover`).
pub(crate) struct Firmware {
    pub executable: Vec<u8>,
    pub pnvm: Option<Vec<u8>>,
}

/// The station state, serialized like the built-in `Device`'s.
struct State {
    hardware: Hardware,
    /// The last scan's beacons: association needs the exact record.
    beacons: Vec<Beacon>,
    connection: Option<Connection>,
    eapol: VecDeque<Vec<u8>>,
    /// The next frame to publish, kept across a lack of queue credit.
    pending: Option<PendingTx<Vec<u8>>>,
    /// The last firmware job failed: restart before the next one.
    needs_reset: bool,
    /// The transport stop after a failure already ran.
    stop_completed: bool,
}

impl State {
    fn clear_transmit(&mut self, queue: &IrqSafeSpinLock<VecDeque<Vec<u8>>>) {
        self.pending = None;
        queue.lock().clear();
    }
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
    policy: mld_policy::Source,
    /// The association's regulatory fence, checked at every publication.
    policy_fence: IrqSafeSpinLock<Option<Fence>>,
    /// Carrier: the association is complete and its port authorized.
    up: AtomicBool,
    /// bit 63 = associated, low 48 bits = BSSID (LE).
    bssid: AtomicU64,
    /// A transport stop could not prove DMA stopped, or a restart failed:
    /// the radio stays down until the module is reloaded.
    dead: AtomicBool,
    /// The host aborted the running scan.
    abort: AtomicBool,
    /// Ethernet frames from the stack, for the TX publication.
    tx: IrqSafeSpinLock<VecDeque<Vec<u8>>>,
    /// The last scan's results, for a `CONNECT` without a BSSID.
    last_scan: IrqSafeSpinLock<Vec<BssInfo>>,
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

/// A `CONNECT` event, decoded.
struct ConnectRequest {
    bssid: [u8; 6],
    frequency_mhz: u32,
    ssid: Vec<u8>,
    auth: AuthMethod,
}

/// `Device::step_owned`'s station-branch output.
#[derive(Default)]
struct Step {
    /// Ethernet frames for the stack.
    output: Vec<Vec<u8>>,
    /// Carrier went down: report `DISCONNECTED`.
    lost: bool,
    /// More work is ready without waiting.
    progress: bool,
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

    /// `Device::set_link(false)`: drop carrier and forget the BSSID. `true`
    /// when carrier was up (the caller reports the loss).
    fn link_down(&self) -> bool {
        self.bssid.store(0, Ordering::Release);
        self.up.swap(false, Ordering::AcqRel)
    }

    /// `Device::publish_link`: carrier on for `bssid`, under the current
    /// regulatory fence.
    fn publish_link(&self, bssid: [u8; 6]) -> Result<(), &'static str> {
        self.policy_current()?;
        let mut packed = 1u64 << 63;
        for (i, byte) in bssid.iter().enumerate() {
            packed |= (*byte as u64) << (8 * i);
        }
        self.bssid.store(packed, Ordering::Release);
        self.up.store(true, Ordering::Release);
        Ok(())
    }

    /// `Device::policy_current`.
    fn policy_current(&self) -> Result<(), &'static str> {
        match self.policy_fence.lock().as_ref() {
            Some(fence) => fence.check(),
            None if !self.link_up() => Ok(()),
            None => Err("Intel station publication lacks current RF policy"),
        }
    }

    /// `Device::install_station_policy`.
    fn install_station_policy(&self, state: &mut State) -> Result<(), &'static str> {
        let program = state
            .connection
            .as_ref()
            .ok_or("Intel station policy lacks association")?
            .regulatory_program();
        let fence = self.policy.bind(program)?;
        state
            .hardware
            .install_rf_policy(mld_policy::Authority::Station(fence.clone()))?;
        *self.policy_fence.lock() = Some(fence);
        Ok(())
    }

    /// `Device::stop_locked`: stop autonomous firmware emission and pin
    /// uncertain DMA. `true` when carrier was up.
    async fn stop_locked(&self, state: &mut State) -> bool {
        let lost = self.link_down();
        state.needs_reset = true;
        state.clear_transmit(&self.tx);
        state.eapol.clear();
        if let Some(connection) = state.connection.as_mut() {
            connection.authorized = false;
        }
        if !state.stop_completed {
            if state.hardware.stop_for_suspend().await.is_err() {
                log(format_args!(
                    "DMA stop not acknowledged; allocations pinned, radio down until reload"
                ));
                self.dead.store(true, Ordering::Release);
            }
            state.stop_completed = true;
        }
        lost
    }

    /// `Device::recover`: restart the firmware from the retained images and
    /// re-run the configuration; the MAC, chains, channels and PHY must come
    /// back unchanged.
    async fn recover(&self, state: &mut State) -> Result<(), WirelessError> {
        if self.dead.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        let _ = self.link_down();
        *self.policy_fence.lock() = None;
        state.hardware.clear_rf_policy();
        state.needs_reset = true;
        state.stop_completed = false;
        state.connection = None;
        state.clear_transmit(&self.tx);
        state.eapol.clear();
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

    /// Recover first when the last job failed or the port is closed.
    async fn ready(&self, state: &mut State) -> Result<(), WirelessError> {
        if state.needs_reset
            || state.hardware.is_failed()
            || state
                .connection
                .as_ref()
                .is_some_and(|connection| !connection.authorized)
        {
            if let Err(error) = self.recover(state).await {
                log(format_args!("firmware restart failed: {:?}", error));
                return Err(error);
            }
        }
        Ok(())
    }

    // ── Scan (`Device::scan`) ─────────────────────────────────────────

    /// The channels a request selects: frequencies are authoritative,
    /// numeric-only selectors keep the legacy 2.4/5 GHz meaning, and an empty
    /// request scans every NVM channel.
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

    async fn scan(&self, mut request: ScanRequest) -> Result<Vec<(BssInfo, Vec<u8>)>, ScanError> {
        if request.ssids.len() > 20 || request.ssids.iter().any(|ssid| ssid.len() > 32) {
            return Err(WirelessError::InvalidArgs.into());
        }
        let channels = self.select_channels(&request)?;
        // Shared RNR planning consumes canonical frequencies.
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
        self.ready(&mut state).await?;
        if state.connection.is_some() {
            return Err(WirelessError::Busy.into());
        }
        state.hardware.clear_rf_policy();
        *self.policy_fence.lock() = None;
        state.needs_reset = true;
        state.stop_completed = false;
        self.abort.store(false, Ordering::Release);
        let outcome = {
            let State {
                hardware, beacons, ..
            } = &mut *state;
            self.scan_jobs(hardware, beacons, &request, &legacy, &six)
                .await
        };
        state.needs_reset = outcome.is_err();
        if outcome.is_ok() {
            state.hardware.clear_rf_policy();
        } else {
            let _ = self.stop_locked(&mut state).await;
        }
        outcome
    }

    /// The scan's firmware jobs (the built-in `Device::scan` body).
    async fn scan_jobs(
        &self,
        hw: &mut Hardware,
        beacons: &mut Vec<Beacon>,
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
            let plan = (phase == 1)
                .then(|| narf_wireless::scan::plan_6ghz_scan(request, &colocated, None));
            let channels: Vec<Channel> = if let Some(plan) = &plan {
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
            if request.active {
                if let Ok(domain) = self.policy.snapshot() {
                    hw.install_rf_policy(mld_policy::Authority::Transaction(
                        self.policy
                            .transaction(&domain)
                            .map_err(|_| WirelessError::HardwareError)?,
                    ))
                    .map_err(|_| WirelessError::HardwareError)?;
                    let permissions =
                        super::super::connection::regulatory_channels_in_domain(hw, &domain)
                            .await
                            .map_err(|_| WirelessError::HardwareError)?;
                    let powers: Vec<_> = channels
                        .iter()
                        .map(|&channel| {
                            if channel.band == Band::Six {
                                six_ghz_scan::power(self.phy, &domain, channel, &permissions)
                            } else {
                                super::super::connection::channel_power(
                                    &domain,
                                    channel.number,
                                    &permissions.channels,
                                    true,
                                )
                            }
                        })
                        .collect();
                    if let Some(power) = powers.iter().flatten().min() {
                        hw.ensure_platform_power()
                            .await
                            .map_err(|_| WirelessError::HardwareError)?;
                        let mut command = station_api::tx_power(
                            hw.version(1, 0x9f).ok_or(WirelessError::NotSupported)?.0,
                            *power,
                        )
                        .map_err(|_| WirelessError::NotSupported)?;
                        command[0] = 1; // Actual SET_DEVICE ceiling for unbound scan probes.
                        let receipt = hw
                            .command(1, 0x9f, &command)
                            .await
                            .map_err(|_| WirelessError::HardwareError)?;
                        if !receipt.payload.is_empty() {
                            return Err(WirelessError::HardwareError.into());
                        }
                    }
                    let permitted: Vec<_> = powers.iter().map(Option::is_some).collect();
                    let mut phy = self.phy;
                    phy.he &= permissions.he_allowed;
                    phy.eht &= phy.he && permissions.eht_allowed && hw.eht_supported();
                    if channels[0].band == Band::Six {
                        body = six_ghz_scan::request(
                            version,
                            uid,
                            &channels,
                            self.mac,
                            &six_ghz_scan::Active {
                                permitted: &permitted,
                                ssids: &request.ssids,
                                targets: plan.as_ref().map_or(&[][..], |p| p.targets.as_slice()),
                                phy,
                                hidden: hw.scan_hidden_six_supported(),
                                tpc: hw.scan_tpc_supported(),
                                fixed: hw.scan_fixed_antenna_supported(),
                                extra_ies: &request.extra_ies,
                            },
                        )
                        .map_err(|_| WirelessError::InvalidArgs)?;
                    } else {
                        let numbers: Vec<_> = channels.iter().map(|ch| ch.number).collect();
                        body = scan_api::active(
                            version,
                            uid,
                            &numbers,
                            &permitted,
                            self.mac,
                            &request.ssids,
                        )
                        .map_err(|_| WirelessError::InvalidArgs)?;
                        scan_api::with_phy_capabilities(version, &mut body, phy)
                            .map_err(|_| WirelessError::InvalidArgs)?;
                    }
                }
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
                    let record = Beacon {
                        bssid,
                        ssid: beacon.ssid.clone(),
                        channel: mpdu.channel,
                        band: channel.band,
                        interval: u16::from_le_bytes([body[8], body[9]]),
                        dtim: scan_api::dtim_period(body),
                        rsn: beacon.rsn_ie_body.clone(),
                        privacy: body[10] & 0x10 != 0,
                        capabilities: u16::from_le_bytes([body[10], body[11]]),
                        information_elements: body[12..].to_vec(),
                    };
                    if let Some(old) = beacons.iter_mut().find(|old| {
                        old.bssid == bssid
                            && old.band == channel.band
                            && old.channel == channel.number
                    }) {
                        *old = record;
                    } else if beacons.len() < SCAN_RESULTS_MAX {
                        beacons.push(record);
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
                    let ies = body[12..].to_vec();
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

    // ── Association (`Device::associate_links`, one link) ────────────

    /// A `CONNECT` that left the BSS to the driver (all-zero BSSID): the
    /// strongest matching network of the last scan
    /// (`cfg80211_get_bss` in `cfg80211_sme_get_conn_ies`).
    fn resolve_bss(&self, mut request: ConnectRequest) -> Option<ConnectRequest> {
        if request.bssid != [0; 6] && request.frequency_mhz != 0 {
            return Some(request);
        }
        let scan = self.last_scan.lock();
        let fits = |bss: &&BssInfo| {
            bss.ssid == request.ssid
                && (request.bssid == [0; 6] || bss.bssid == request.bssid)
                && match request.auth {
                    AuthMethod::Open => matches!(bss.security, BssSecurity::Open),
                    AuthMethod::Wpa2Psk(_) => {
                        matches!(bss.security, BssSecurity::Wpa2 | BssSecurity::Wpa3)
                    }
                    AuthMethod::Wpa3Sae { .. } => {
                        matches!(bss.security, BssSecurity::Wpa2 | BssSecurity::Wpa3)
                    }
                }
        };
        let bss = scan.iter().filter(fits).max_by_key(|bss| bss.rssi)?;
        request.bssid = bss.bssid;
        request.frequency_mhz = bss.frequency_mhz;
        Some(request)
    }

    async fn associate(&self, request: ConnectRequest) -> Result<[u8; 6], WirelessError> {
        if request.ssid.is_empty() || request.ssid.len() > 32 || request.bssid[0] & 1 != 0 {
            return Err(WirelessError::InvalidArgs);
        }
        let domain = self
            .policy
            .request_snapshot()
            .map_err(|_| WirelessError::HardwareError)?;
        let mut state = self.state.try_lock().ok_or(WirelessError::Busy)?;
        self.ready(&mut state).await?;
        if state.connection.is_some() {
            return Err(WirelessError::Busy);
        }
        let beacon = state
            .beacons
            .iter()
            .find(|b| {
                b.bssid == request.bssid
                    && b.ssid == request.ssid
                    && Channel {
                        band: b.band,
                        number: b.channel,
                    }
                    .frequency()
                        == request.frequency_mhz
            })
            .cloned()
            .ok_or(WirelessError::InvalidArgs)?;
        // Cancellation leaves this set: the service fails closed rather
        // than driving partially configured station/queue state.
        state.needs_reset = true;
        state.stop_completed = false;
        state
            .hardware
            .install_rf_policy(mld_policy::Authority::Transaction(
                self.policy
                    .transaction(&domain)
                    .map_err(|_| WirelessError::HardwareError)?,
            ))
            .map_err(|_| WirelessError::HardwareError)?;
        let bssid = request.bssid;
        match Connection::associate_links_in_domain(
            &mut state.hardware,
            self.mac,
            beacon,
            request.auth,
            self.tx_chains,
            self.phy,
            None,
            &domain,
            None,
            Vec::new(),
        )
        .await
        {
            Ok(connection) => {
                state.connection = Some(*connection);
                if self.install_station_policy(&mut state).is_err() {
                    let _ = self.stop_locked(&mut state).await;
                    return Err(WirelessError::HardwareError);
                }
                state.needs_reset = false;
                if self.publish_link(bssid).is_err() {
                    let _ = self.stop_locked(&mut state).await;
                    return Err(WirelessError::HardwareError);
                }
                Ok(bssid)
            }
            Err(error) => {
                log(format_args!("association failed: {}", error));
                let _ = self.stop_locked(&mut state).await;
                Err(WirelessError::HardwareError)
            }
        }
    }

    /// `Device::disassociate` / `close_locked`.
    async fn disassociate(&self) -> Result<(), WirelessError> {
        let _ = self.link_down();
        let mut state = self.state.lock().await;
        state.clear_transmit(&self.tx);
        state.eapol.clear();
        if state.connection.is_none() && (state.needs_reset || state.hardware.is_failed()) {
            let _ = self.stop_locked(&mut state).await;
            return if self.dead.load(Ordering::Acquire) {
                Err(WirelessError::HardwareError)
            } else {
                Ok(())
            };
        }
        if let Some(connection) = state.connection.take() {
            state.needs_reset = true;
            if connection.disconnect(&mut state.hardware).await.is_err() {
                let _ = self.stop_locked(&mut state).await;
                return Err(WirelessError::HardwareError);
            }
            state.hardware.clear_rf_policy();
            *self.policy_fence.lock() = None;
            state.needs_reset = false;
        }
        Ok(())
    }

    // ── Service (`Device::step_owned`, station branch) ───────────────

    async fn step(&self, state: &mut State) -> Step {
        let mut step = Step::default();
        if self.dead.load(Ordering::Acquire) {
            return step;
        }
        if self.link_up() && self.policy_current().is_err() {
            step.lost = self.stop_locked(state).await;
            return step;
        }
        if state.needs_reset {
            // A failure ran (or must run) the bounded transport stop; the
            // next scan or connect restarts the firmware.
            if !state.stop_completed {
                step.lost = self.stop_locked(state).await;
            }
            return step;
        }
        if state.hardware.poll().is_err() {
            step.lost = self.stop_locked(state).await;
            return step;
        }
        let mut receive_failed = false;
        {
            let State {
                hardware,
                connection,
                eapol,
                ..
            } = &mut *state;
            hardware.retire_transmits();
            if let Some(connection) = connection {
                for _ in 0..RECEIVE_BUDGET {
                    let Some(packet) = hardware.notifications.pop_front() else {
                        break;
                    };
                    match connection
                        .receive_packet_checked(&packet, hardware.rx_checksum_includes_snap())
                    {
                        Ok(frames) => {
                            for (bytes, _meta) in frames {
                                queue_ethernet(bytes, connection.authorized, eapol, &mut step);
                            }
                        }
                        Err(_) => {
                            connection.authorized = false;
                            receive_failed = true;
                            break;
                        }
                    }
                }
                // The WIFI v2 host has no CQM event; the loss itself is
                // reported below once the beacon bound expires.
                let _ = connection.take_cqm_beacon_loss();
                match connection.reorder_tick() {
                    Ok(frames) => {
                        for bytes in frames {
                            queue_ethernet(bytes, connection.authorized, eapol, &mut step);
                        }
                    }
                    Err(_) => {
                        connection.authorized = false;
                        receive_failed = true;
                    }
                }
                if narf_time::now_cycles().wrapping_sub(connection.last_beacon)
                    > narf_time::wall::ns_to_cycles(BEACON_LOSS_NS)
                {
                    connection.authorized = false;
                    receive_failed = true;
                }
            } else {
                hardware.notifications.clear();
            }
        }
        if receive_failed {
            // Closing carrier alone leaves firmware's autonomous station and
            // DMA alive: run the bounded transport stop.
            step.output.clear();
            step.lost = self.stop_locked(state).await;
            return step;
        }
        let maintenance = state.connection.as_ref().is_some_and(|connection| {
            connection.authorized && (!state.eapol.is_empty() || connection.maintenance_pending())
        });
        if maintenance {
            // `Device::start_control`'s work, inline: this task owns State.
            let result = async {
                let State {
                    hardware,
                    connection,
                    eapol,
                    ..
                } = &mut *state;
                if let Some(connection) = connection {
                    connection.set_scheduled_scan_busy(false);
                    for _ in 0..16 {
                        let Some(frame) = eapol.pop_front() else {
                            break;
                        };
                        connection.handle_eapol(hardware, &frame).await?;
                    }
                    connection.service_aggregation(hardware).await?;
                } else {
                    eapol.clear();
                }
                Ok::<(), &'static str>(())
            }
            .await;
            if result.is_err() {
                state.hardware.fail();
                step.output.clear();
                step.lost = self.stop_locked(state).await;
                return step;
            }
            step.progress = true;
        } else if !self.link_up() {
            state.clear_transmit(&self.tx);
        } else {
            match self.progress_transmit(state) {
                Ok(progress) => step.progress |= progress,
                Err(_) => {
                    state.hardware.fail();
                    step.output.clear();
                    step.lost = self.stop_locked(state).await;
                    return step;
                }
            }
        }
        // RX publication fence (`Device::refresh_receive_ipc` + delivery):
        // carrier, the authorized port, the current receive epoch and the
        // current regulatory fence.
        let current = self.link_up()
            && state.eapol.is_empty()
            && state.connection.as_ref().is_some_and(|c| c.authorized)
            && state
                .hardware
                .receive_publication()
                .is_some_and(|receive| receive.current())
            && self.policy_current().is_ok();
        if !current {
            step.output.clear();
        }
        step.progress |=
            state.hardware.has_pending_rx() || !state.hardware.notifications.is_empty();
        step
    }

    /// `State::progress_transmit`, one category queue: publish the pending
    /// frame when the station has queue credit (the connection classifies
    /// its access category). `true` when a frame went out.
    fn progress_transmit(&self, state: &mut State) -> Result<bool, &'static str> {
        let State {
            hardware,
            connection,
            pending,
            ..
        } = &mut *state;
        let Some(connection) = connection.as_mut().filter(|c| c.authorized) else {
            *pending = None;
            self.tx.lock().clear();
            return Ok(false);
        };
        let mut sent = false;
        for _ in 0..64 {
            if pending.is_none() {
                *pending = self.tx.lock().pop_front().map(PendingTx::new);
            }
            let Some(frame) = pending.as_ref() else {
                break;
            };
            match frame
                .progress(|bytes| connection.try_enqueue_assisted(hardware, bytes, None, 0))?
            {
                Transmit::Sent => {
                    *pending = None;
                    sent = true;
                }
                Transmit::Busy => break,
                Transmit::Expired => return Err("TX queue credit timed out"),
            }
        }
        Ok(sent)
    }

    /// Deliver received frames to the stack (`narf_netif_rx`).
    fn deliver(&self, frames: Vec<Vec<u8>>) {
        for mut frame in frames {
            // SAFETY: `frame` names `len` bytes the call may rewrite in place.
            let _ = unsafe {
                ffi::narf_netif_rx(
                    super::device(),
                    self.ifindex,
                    frame.as_mut_ptr(),
                    frame.len(),
                )
            };
        }
    }

    /// The radio's service task (`Device::pump`).
    async fn service(self: Arc<Self>) {
        let mut refreshed = narf_time::now_cycles();
        loop {
            if self.dead.load(Ordering::Acquire) {
                if self.link_down() {
                    self.report_loss();
                }
                return;
            }
            let now = narf_time::now_cycles();
            if now.wrapping_sub(refreshed) >= narf_time::wall::ns_to_cycles(REGULATORY_REFRESH_NS) {
                // A changed kernel domain replaces the snapshot; the station
                // fence then fails and carrier drops, as built in.
                regulatory::refresh();
                refreshed = now;
            }
            let (activity, step) = match self.state.try_lock() {
                Some(mut state) => {
                    let activity = state.hardware.activity();
                    let step = self.step(&mut state).await;
                    (Some(activity), step)
                }
                None => (None, Step::default()),
            };
            let Step {
                output,
                lost,
                progress,
            } = step;
            self.deliver(output);
            if lost {
                self.report_loss();
            }
            if progress {
                narf_module_rt::time::yield_now().await;
                continue;
            }
            match activity {
                Some(activity) => activity.await,
                None => narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await,
            }
        }
    }

    /// Unsolicited carrier loss (`notify_disconnect(name, 1, false)` built in).
    fn report_loss(&self) {
        let _ = self.report(
            wifi::OP_DISCONNECTED,
            &encode_disconnected(wifi::REASON_UNSPECIFIED, false),
        );
    }
}

/// `Device`'s `queue_ethernet`: EAPOL to the in-driver supplicant, data to
/// the stack once the port is authorized.
fn queue_ethernet(
    bytes: Vec<u8>,
    authorized: bool,
    eapol: &mut VecDeque<Vec<u8>>,
    step: &mut Step,
) {
    if bytes.len() >= 14 && bytes[12..14] == [0x88, 0x8e] {
        if eapol.len() < 16 {
            eapol.push_back(bytes);
        }
    } else if authorized {
        step.output.push(bytes);
    }
}

/// Netif TX: the stack hands one Ethernet frame (borrowed for this call).
extern "C" fn tx_callback(_dev: u64, frame: *const u8, len: usize) -> i32 {
    let Some(radio) = radio() else {
        return ENODEV;
    };
    if frame.is_null() || len < 14 || !radio.link_up() {
        return ENOBUFS;
    }
    // SAFETY: the bridge lends `len` readable bytes for the call.
    let bytes = unsafe { core::slice::from_raw_parts(frame, len) }.to_vec();
    let mut queue = radio.tx.lock();
    if queue.len() >= TX_QUEUE_MAX {
        return ENOBUFS;
    }
    queue.push_back(bytes);
    0
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
            let Some(request) = decode_connect(&bytes) else {
                return EINVAL;
            };
            let _ = super::EXEC.spawn(async move { connect_and_report(&radio, request).await });
            0
        }
        wifi::EVENT_DISCONNECT => {
            let _ = super::EXEC.spawn(async move {
                if radio.disassociate().await.is_err() {
                    log(format_args!("disconnect stopped the transport"));
                }
                // Reported after the native teardown, and also when not
                // associated, so the host's wait completes.
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
            *radio.last_scan.lock() = results.iter().map(|(bss, _)| bss.clone()).collect();
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

async fn connect_and_report(radio: &Radio, request: ConnectRequest) {
    let (bssid, frequency) = (request.bssid, request.frequency_mhz);
    let result = match radio.resolve_bss(request) {
        Some(request) => {
            let frequency = request.frequency_mhz;
            radio
                .associate(request)
                .await
                .map(|bssid| (bssid, frequency))
        }
        None => Err(WirelessError::InvalidArgs),
    };
    match result {
        Ok((bssid, frequency)) => {
            let _ = radio.report(
                wifi::OP_CONNECT_RESULT,
                &encode_connect_result(0, bssid, frequency),
            );
        }
        Err(error) => {
            log(format_args!("connect failed: {:?}", error));
            let _ = radio.report(
                wifi::OP_CONNECT_RESULT,
                &encode_connect_result(wifi::STATUS_UNSPECIFIED_FAILURE, bssid, frequency),
            );
        }
    }
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

/// Decode `CONNECT` (`module_host::encode_connect`): Open, a 32-byte PMK, or
/// an SAE password.
fn decode_connect(b: &[u8]) -> Option<ConnectRequest> {
    if b.len() < 20 || b[7] != 0 || b[13] != 0 || b[18..20] != [0, 0] {
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
    let secret_at = 20 + ssid_len + ie_len;
    let secret = b.get(secret_at..secret_at + secret_len)?;
    if secret_at + secret_len != b.len() {
        return None;
    }
    let auth = match security {
        wifi::SECURITY_OPEN if secret.is_empty() => AuthMethod::Open,
        wifi::SECURITY_PSK => AuthMethod::Wpa2Psk(secret.try_into().ok()?),
        wifi::SECURITY_SAE if !secret.is_empty() => AuthMethod::Wpa3Sae {
            password: secret.to_vec(),
        },
        _ => return None,
    };
    Some(ConnectRequest {
        bssid,
        frequency_mhz,
        ssid,
        auth,
    })
}

/// `REGISTER_WIPHY` from the NVM (the built-in `get_wireless_info`, station
/// subset): station mode, the NVM's channels per band, HT/VHT/HE/EHT, CCMP
/// (the built-in station's suite) and the in-driver SME.
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
    out.push(wifi::FLAG_PSK_OFFLOAD | wifi::FLAG_SAE_OFFLOAD | wifi::FLAG_REPORTS_DISCONNECT);
    out.push(wifi::MAX_SCAN_SSIDS);
    out.push(0);
    out.extend_from_slice(&wifi::MAX_SCAN_IE_LEN.to_le_bytes());
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

/// Open the device's `WIFI` session (before the netdev, so the bridge names
/// it `wlan%d`) and bind the regulatory queries to it. `None` when refused.
pub(crate) fn open_session() -> Option<u64> {
    let mut session = 0u64;
    // SAFETY: `event_callback` is a valid extern "C" fn in this image;
    // `session` is a live local.
    let rc = unsafe {
        ffi::narf_wireless_open_with_event(
            super::device(),
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
        return None;
    }
    regulatory::set_session(session);
    Some(session)
}

/// Publish the radio (the module build's `start_pumps` + registration):
/// netdev, wiphy, then the service task.
pub(crate) fn publish(
    session: u64,
    hardware: Hardware,
    mac: [u8; 6],
    nvm: station_api::Nvm,
    firmware: Firmware,
) {
    let mut ifindex = 0u32;
    // SAFETY: `mac` names six readable bytes; `tx_callback` is a valid extern
    // "C" fn in this image; `ifindex` is a live local.
    let rc = unsafe {
        ffi::narf_netif_register_with_context(
            super::device(),
            mac.as_ptr(),
            tx_callback as usize,
            &mut ifindex,
        )
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
            beacons: Vec::new(),
            connection: None,
            eapol: VecDeque::new(),
            pending: None,
            needs_reset: false,
            stop_completed: false,
        }),
        policy: mld_policy::Source::native(),
        policy_fence: IrqSafeSpinLock::new(None),
        up: AtomicBool::new(false),
        bssid: AtomicU64::new(0),
        dead: AtomicBool::new(false),
        abort: AtomicBool::new(false),
        tx: IrqSafeSpinLock::new(VecDeque::new()),
        last_scan: IrqSafeSpinLock::new(Vec::new()),
    });
    let rc = radio.report(wifi::OP_REGISTER_WIPHY, &encode_register_wiphy(&radio));
    if rc != 0 {
        log(format_args!("wiphy registration refused ({rc})"));
    } else {
        log(format_args!("wlan (ifindex {ifindex}) up"));
    }
    *RADIO.lock() = Some(radio.clone());
    let _ = super::EXEC.spawn(radio.service());
}

/// The associated BSSID, for diagnostics.
pub(crate) fn connected_bssid() -> Option<[u8; 6]> {
    radio().and_then(|radio| radio.connected())
}
