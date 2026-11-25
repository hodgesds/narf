//! The module build's netdev (`ath10k.ko`): the station data path and
//! control plane behind the KABI.
//!
//! Built in, [`super::interface`] is a full mac80211-shaped netdev (frame
//! rings, AP/P2P/ROC roles, WoW and system PM, power save, reconnect after
//! recovery, external-SME MLME and control port). A module reaches the
//! network stack only through the netif bridge and the `WIFI` family host
//! (`wireless/src/module_host.rs`, version 2), so this is the station
//! subset over the same retained radio (`wmi_runtime::Radio`) the built-in
//! netdev drives, call for call:
//!
//! - **netdev** — `narf_netif_register_with_context` (the bridge names it
//!   `wlan%d` because the device has a wireless session); TX frames arrive
//!   in [`tx_callback`], RX goes out through `narf_netif_rx`;
//! - **wiphy** — `REGISTER_WIPHY` binds the shell to that netdev and
//!   advertises the radio's channels, HT/VHT, CCMP and the in-driver SME
//!   (PSK and SAE offload, as the built-in netdev's `supports_handshake_
//!   offload`);
//! - **control** — the host's `SCAN_REQUEST` / `CONNECT` / `DISCONNECT`
//!   events run [`ModuleNetdev::scan`] / [`ModuleNetdev::associate`] /
//!   [`ModuleNetdev::disassociate`] (the built-in `Device` paths: native
//!   scan, coexistence preflight, peer preparation, Open/WPA2-PSK/WPA3-SAE
//!   association and the in-driver 4-way handshake), whose outcomes go back
//!   as `SCAN_RESULT` / `SCAN_DONE` / `CONNECT_RESULT` / `DISCONNECTED`;
//! - **service** — one worker per radio, the built-in worker minus its ROC
//!   and power-save steps: failed-scan cleanup, the data drain (RX to the
//!   stack, queued TX into HTT, carrier), PMF management flush, then a wait
//!   on the transport's interrupt signal or the polling backstop.
//!
//! - **recovery** — the built-in automatic recovery (`pci.rs`, `restart.rs`)
//!   runs unchanged: a firmware crash or a failed scan cleanup retires the
//!   generation ([`retire`]) and boots a fresh-ROM one, bounded at three
//!   attempts per load. The netdev, its `WIFI` session and wiphy outlive the
//!   generation (mac80211 `ieee80211_restart_hw` keeps the netdev too): the
//!   next generation's [`wait_publish`] rebinds them, and replays the
//!   retained association like the built-in `replay_retained`
//!   (`ieee80211_sta_restart` + wpa_supplicant reconnecting).
//!
//! As built in, a disconnect or an abandoned association closes the
//! retained radio owner (`Radio::disconnect_station`); a later association
//! needs a fresh generation.
//!
//! Not carried (built-in only): AP/P2P/ROC, WoW and system PM, power-save
//! control (the awake default is still submitted), the userspace SME, and
//! the kernel's live regulatory database (see `platform::reg`).

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use narf_wireless::scan::BssSecurity;
use narf_wireless::{AssociateRequest, BssInfo, ScanRequest, SecurityConfig, WirelessError};

use super::boot::PciBoot;
use super::platform::{self, Console, IrqSafeSpinLock, Mutex};
use super::regulatory::Permission;
use super::wmi_runtime::{self, Radio};

type Error = wmi_runtime::Error;
type SharedRadio = Arc<Mutex<Radio<PciBoot>>>;

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
    /// IEEE 802.11 reason: deauthenticated because the station is leaving.
    pub const REASON_DEAUTH_LEAVING: u16 = 3;
    /// IEEE 802.11 reason: unspecified (link lost without a frame).
    pub const REASON_UNSPECIFIED: u16 = 1;
}

/// TX frames queued between the stack and the worker.
const TX_QUEUE_MAX: usize = 512;
/// Frames the worker hands HTT per drain (the built-in drain's bound).
const TX_BATCH: usize = 16;
/// ath10k's noise floor (`ATH10K_DEFAULT_NOISE_FLOOR`): RSSI = NF + SNR.
const NOISE_FLOOR: i32 = -95;
const ENOBUFS: i32 = -105;

/// The station netdev of the module build.
#[allow(missing_debug_implementations)]
pub(super) struct ModuleNetdev {
    radio: SharedRadio,
    /// The PCI owner's generation quarantine (`pci.rs` `RadioSession`).
    quarantine: Arc<AtomicBool>,
    mac: [u8; 6],
    ifindex: u32,
    session: u64,
    /// Supported station frequencies (the built-in netdev's list).
    frequencies: Vec<u16>,
    /// bit 63 = associated, low 48 bits = BSSID (LE).
    bssid: AtomicU64,
    up: AtomicBool,
    /// Data faults close the netdev, as the built-in `close`.
    closed: AtomicBool,
    /// This generation was retired for recovery (`retire`).
    dead: AtomicBool,
    /// An association is being set up (refuses a second one).
    joining: AtomicBool,
    tx: IrqSafeSpinLock<VecDeque<Vec<u8>>>,
    /// The last scan's networks, for a `CONNECT` without a BSSID.
    last_scan: IrqSafeSpinLock<Vec<BssInfo>>,
    signal: Arc<super::irq::Signal>,
    delivered: bool,
}

/// The one radio's current generation (ath10k is single-instance).
/// Callbacks find it here; `None` between a retirement and the next
/// generation's publication.
static NETDEV: IrqSafeSpinLock<Option<Arc<ModuleNetdev>>> = IrqSafeSpinLock::new(None);

/// What outlives a generation: the `WIFI` session, the netdev and the MAC
/// they were registered with (the firmware/OTP address, unchanged across
/// recovery), and the association to replay.
struct Shell {
    session: u64,
    ifindex: u32,
    mac: [u8; 6],
}
static SHELL: IrqSafeSpinLock<Option<Shell>> = IrqSafeSpinLock::new(None);

/// The retained network block (the built-in `narf_wireless::reconnect`
/// profile): kept by a completed association, forgotten by an operator
/// disconnect, replayed once by the next generation.
struct Profile {
    bssid: [u8; 6],
    ssid: Vec<u8>,
    frequency_mhz: u32,
    channel: u32,
    /// `wifi::SECURITY_*`.
    security: u8,
    secret: zeroize::Zeroizing<Vec<u8>>,
    ie: Vec<u8>,
}
impl Profile {
    fn capture(request: &AssociateRequest) -> Option<Self> {
        let (security, secret) = match &request.security {
            SecurityConfig::Open => (wifi::SECURITY_OPEN, Vec::new()),
            SecurityConfig::Wpa2 { psk } => (wifi::SECURITY_PSK, psk.to_vec()),
            SecurityConfig::Wpa3 { password } => (wifi::SECURITY_SAE, password.clone()),
            _ => return None,
        };
        Some(Self {
            bssid: request.bssid,
            ssid: request.ssid.clone(),
            frequency_mhz: request.frequency_mhz,
            channel: request.channel,
            security,
            secret: zeroize::Zeroizing::new(secret),
            ie: request.ie.clone(),
        })
    }
    fn request(&self) -> Option<AssociateRequest> {
        let security = match self.security {
            wifi::SECURITY_OPEN => SecurityConfig::Open,
            wifi::SECURITY_PSK => SecurityConfig::Wpa2 {
                psk: self.secret.as_slice().try_into().ok()?,
            },
            wifi::SECURITY_SAE => SecurityConfig::Wpa3 {
                password: self.secret.to_vec(),
            },
            _ => return None,
        };
        Some(AssociateRequest {
            bssid: self.bssid,
            ssid: self.ssid.clone(),
            frequency_mhz: self.frequency_mhz,
            channel: self.channel,
            security,
            ie: self.ie.clone(),
        })
    }
}
static PROFILE: IrqSafeSpinLock<Option<Profile>> = IrqSafeSpinLock::new(None);

fn netdev() -> Option<Arc<ModuleNetdev>> {
    NETDEV.lock().clone()
}

fn log(args: core::fmt::Arguments<'_>) {
    let _ = writeln!(Console, "  ath10k.ko: {}", args);
}

/// The built-in netdev's error mapping.
fn error(value: Error) -> WirelessError {
    match value {
        Error::Unsupported => WirelessError::NotSupported,
        Error::Timeout => WirelessError::Timeout,
        Error::Htt(super::htt_runtime::Error::Busy) => WirelessError::Busy,
        _ => WirelessError::HardwareError,
    }
}

/// The module's regulatory domain (`platform::reg`), as `Policy::current`.
fn current_domain() -> Result<narf_wireless::reg::RegulatoryDomain, Error> {
    platform::reg::get_domain().ok_or(Error::Unsupported)
}

/// The built-in netdev's `admitted`: an Ethernet frame from this station,
/// with no EAPOL/WAI/IPX (the in-driver supplicant owns EAPOL).
fn admitted(bytes: &[u8], own: [u8; 6]) -> bool {
    (14..=1514).contains(&bytes.len())
        && bytes[6..12] == own
        && bytes[..6] != [0; 6]
        && u16::from_be_bytes([bytes[12], bytes[13]]) >= 0x600
        && !matches!(
            u16::from_be_bytes([bytes[12], bytes[13]]),
            0x888e | 0x80f3 | 0x8137
        )
}

/// The nl80211 view of one scan-report BSS (the built-in `bss_info`, with
/// the signal Linux derives from the reported SNR).
fn bss_info(b: wmi_runtime::ScanBss) -> BssInfo {
    let secured = b.capability & 16 != 0;
    BssInfo {
        bssid: b.bssid,
        ssid: b.ssid,
        channel: narf_wireless::association::channel::from_frequency(u32::from(b.frequency))
            .map(u32::from)
            .unwrap_or(0),
        frequency_mhz: u32::from(b.frequency),
        rssi: (NOISE_FLOOR + b.snr.min(127) as i32).clamp(-128, 0) as i8,
        security: if secured {
            BssSecurity::Wpa2
        } else {
            BssSecurity::Open
        },
    }
}

/// Closes the netdev if an attempt is abandoned half way (the built-in
/// `Attempt`).
struct Attempt<'a> {
    device: &'a ModuleNetdev,
    armed: bool,
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.device.close();
        }
    }
}

impl ModuleNetdev {
    fn stopped(&self) -> bool {
        self.dead.load(Ordering::Acquire)
            || self.quarantine.load(Ordering::Acquire)
            || self.closed.load(Ordering::Acquire)
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

    /// Carrier on/off with the peer (the built-in `publish_link`): a lost
    /// carrier is reported to the host as `DISCONNECTED`.
    fn publish_link(&self, peer: Option<[u8; 6]>, why: (u16, bool)) {
        let peer = peer.filter(|_| !self.stopped());
        let mut packed = 0u64;
        if let Some(peer) = peer {
            packed = 1 << 63;
            for (i, byte) in peer.iter().enumerate() {
                packed |= u64::from(*byte) << (8 * i);
            }
        }
        self.bssid.store(packed, Ordering::Release);
        let up = peer.is_some();
        let was = self.up.swap(up, Ordering::AcqRel);
        if was && !up {
            let _ = self.report(wifi::OP_DISCONNECTED, &encode_disconnected(why.0, why.1));
        }
    }

    /// The built-in `close`: no further data; carrier off.
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.publish_link(None, (wifi::REASON_UNSPECIFIED, true));
        self.signal.raise();
    }

    /// The built-in `Device::scan_frequencies`, station subset.
    fn scan_frequencies(
        &self,
        request: &mut ScanRequest,
    ) -> Result<(Vec<u16>, bool), WirelessError> {
        if request.random_mac.is_some()
            || request.colocated_6ghz
            || request.duration_tu.is_some()
            || request.duration_mandatory
            || (!request.active && !request.extra_ies.is_empty())
            || request.ssids.len() > wmi_runtime::MAX_SCAN_SSIDS
            || request.ssids.iter().any(|s| s.len() > 32)
        {
            return Err(WirelessError::NotSupported);
        }
        wmi_runtime::validate_probe_ies(&request.extra_ies).map_err(|err| match err {
            Error::Malformed => WirelessError::InvalidArgs,
            err => error(err),
        })?;
        if request.active && request.ssids.is_empty() {
            request.ssids.push(Vec::new());
        }
        let implicit = request.frequencies_mhz.is_empty() && request.channels.is_empty();
        let frequencies = if !request.frequencies_mhz.is_empty() {
            request
                .frequencies_mhz
                .iter()
                .map(|f| u16::try_from(*f).map_err(|_| WirelessError::InvalidArgs))
                .collect::<Result<Vec<_>, _>>()?
        } else if !request.channels.is_empty() {
            request
                .channels
                .iter()
                .map(|ch| {
                    u8::try_from(*ch)
                        .ok()
                        .and_then(narf_wireless::association::channel::frequency)
                        .and_then(|f| u16::try_from(f).ok())
                        .ok_or(WirelessError::InvalidArgs)
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            self.frequencies.clone()
        };
        if frequencies.is_empty()
            || frequencies
                .iter()
                .any(|f| !Permission::station_frequency(*f) || !self.frequencies.contains(f))
        {
            return Err(WirelessError::NotSupported);
        }
        Ok((frequencies, implicit))
    }

    /// The built-in `Device::scan`: active or passive native scan, or the
    /// associated dwell scan with the data path kept serviced.
    pub(super) async fn scan(
        &self,
        mut request: ScanRequest,
    ) -> Result<Vec<(BssInfo, Vec<u8>)>, WirelessError> {
        if self.stopped() {
            return Err(WirelessError::HardwareError);
        }
        let (mut frequencies, implicit) = self.scan_frequencies(&mut request)?;
        let mut radio = self.radio.lock().await;
        if radio.roc_active() || (radio.prepared_peer().is_some() && radio.station_link().is_none())
        {
            return Err(WirelessError::Busy);
        }
        let domain = current_domain().map_err(error)?;
        if implicit {
            frequencies.retain(|f| {
                wmi_runtime::receive_permission(&domain, &[*f]).is_ok()
                    && (!request.active || radio.active_frequency_allowed(&domain, *f))
            });
        }
        wmi_runtime::receive_permission(&domain, &frequencies).map_err(error)?;
        let associated = radio.station_link().is_some();
        let active = if request.active {
            Some(
                radio
                    .prepare_active_scan(&frequencies, &request.ssids, &domain)
                    .and_then(|plan| plan.with_extra_ies(&request.extra_ies))
                    .map_err(error)?,
            )
        } else if associated {
            Some(
                radio
                    .prepare_associated_passive_scan(&frequencies, &domain)
                    .map_err(error)?,
            )
        } else {
            None
        };
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        let current = || {
            if self.dead.load(Ordering::Acquire) {
                return Err(Error::Failed);
            }
            current_domain()
        };
        let report = if associated {
            radio
                .begin_associated_scan(active.ok_or(WirelessError::HardwareError)?, current)
                .await
                .map_err(|cause| {
                    radio.fail_station_data();
                    error(cause)
                })?;
            drop(radio);
            self.signal.raise();
            loop {
                current().map_err(error)?;
                self.drain();
                {
                    let mut radio = self.radio.lock().await;
                    if radio
                        .associated_scan_complete(&current().map_err(error)?)
                        .map_err(error)?
                    {
                        break radio.finish_associated_scan(current).await.map_err(error);
                    }
                }
                platform::yield_now().await;
            }
        } else if let Some(plan) = active {
            radio.active_scan(plan, current).await.map_err(error)
        } else {
            radio
                .passive_scan_current(&frequencies, current)
                .await
                .map_err(error)
        }?;
        let result: Vec<(BssInfo, Vec<u8>)> = report
            .bss
            .into_iter()
            .filter(|b| {
                request.ssids.is_empty()
                    || request.ssids.iter().any(|s| s.is_empty() || *s == b.ssid)
            })
            .map(|b| {
                let ies = b.information_elements.clone();
                (bss_info(b), ies)
            })
            .collect();
        attempt.armed = false;
        *self.last_scan.lock() = result.iter().map(|(b, _)| b.clone()).collect();
        Ok(result)
    }

    /// The built-in `Device::associate_inner` without power save or the
    /// reconnect profile: coexistence preflight, peer preparation, Open /
    /// WPA2-PSK / WPA3-SAE association, then the data owner (in-driver
    /// 4-way handshake for RSN) and carrier.
    pub(super) async fn associate(&self, request: AssociateRequest) -> Result<(), WirelessError> {
        if self.stopped() {
            return Err(WirelessError::HardwareError);
        }
        if self.up.load(Ordering::Acquire) || self.joining.swap(true, Ordering::AcqRel) {
            return Err(WirelessError::Busy);
        }
        let profile = Profile::capture(&request);
        let result = self.associate_inner(request).await;
        self.joining.store(false, Ordering::Release);
        if result.is_ok() {
            *PROFILE.lock() = profile;
        }
        result
    }

    async fn associate_inner(&self, request: AssociateRequest) -> Result<(), WirelessError> {
        if u16::try_from(request.frequency_mhz)
            .ok()
            .is_none_or(|f| !Permission::station_frequency(f) || !self.frequencies.contains(&f))
            || narf_wireless::association::channel::from_frequency(request.frequency_mhz)
                .map(u32::from)
                != Some(request.channel)
        {
            return Err(WirelessError::NotSupported);
        }
        let (mode, pmk, password) = match &request.security {
            SecurityConfig::Open => (narf_wireless::association::SecurityMode::Open, None, None),
            SecurityConfig::Wpa2 { psk } => (
                narf_wireless::association::SecurityMode::Wpa2Psk,
                Some(zeroize::Zeroizing::new(*psk)),
                None,
            ),
            SecurityConfig::Wpa3 { password } if !password.is_empty() => (
                narf_wireless::association::SecurityMode::Wpa3Sae {
                    pwe: narf_wireless::association::SaePwe::Both,
                },
                None,
                Some(zeroize::Zeroizing::new(password.clone())),
            ),
            _ => return Err(WirelessError::NotSupported),
        };
        let mut radio = self.radio.lock().await;
        if radio.roc_active() {
            return Err(WirelessError::Busy);
        }
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        self.tx.lock().clear();
        let domain = current_domain().map_err(error)?;
        let frequency = request.frequency_mhz as u16;
        radio
            .prepare_coexistence(&domain, request.bssid, frequency, &|| {
                if self.stopped() {
                    return Err(Error::Failed);
                }
                Ok(())
            })
            .await
            .map_err(error)?;
        let permission = radio
            .station_permission(&domain, request.bssid, frequency)
            .map_err(error)?;
        let validate = || {
            if self.stopped() {
                return Err(Error::Failed);
            }
            permission.check(&current_domain()?)
        };
        wmi_runtime::checked_policy(
            radio.prepare_station_checked(&domain, request.bssid, frequency, &validate),
            &validate,
        )
        .await
        .map_err(error)?;
        match password.as_deref() {
            Some(password) => {
                wmi_runtime::checked_policy(
                    radio.associate_station_sae_checked(
                        &domain,
                        &request.ssid,
                        password,
                        &request.ie,
                        &validate,
                    ),
                    &validate,
                )
                .await
            }
            None => {
                wmi_runtime::checked_policy(
                    radio.associate_station_checked(
                        &domain,
                        &request.ssid,
                        mode,
                        &request.ie,
                        &validate,
                    ),
                    &validate,
                )
                .await
            }
        }
        .map_err(error)?;
        let nonce = || {
            let mut nonce = [0; 32];
            narf_crypto::try_fill_random_bytes(&mut nonce)
                .ok()
                .map(|()| nonce)
        };
        let link = wmi_runtime::checked_policy(
            radio.start_data_with_nonce_checked(&domain, pmk.as_deref(), nonce, &validate),
            &validate,
        )
        .await
        .map_err(error)?;
        radio
            .check_data_policy(&current_domain().map_err(error)?)
            .map_err(error)?;
        // The built-in netdev submits its advertised awake default before
        // the first carrier (`ps_request` starts at "off" when the firmware
        // supports power save). The `WIFI` host carries no power-save
        // control, so the module keeps that default for the association.
        if radio.power_save_supported() {
            let result = radio
                .set_station_power_save(false, || {
                    if self.stopped() {
                        return Err(Error::Failed);
                    }
                    current_domain()
                })
                .await;
            if let Err(cause) = result {
                radio.fail_station_data();
                return Err(error(cause));
            }
        }
        if self.stopped() {
            radio.fail_station_data();
            return Err(WirelessError::HardwareError);
        }
        let source = radio.htt.wmi.htc.transport.current_sources();
        drop(radio);
        super::firmware_source::invoke(source.as_ref(), || {
            self.publish_link(Some(link.bssid), (wifi::REASON_UNSPECIFIED, true))
        })
        .map_err(|_| WirelessError::HardwareError)?;
        attempt.armed = false;
        let _ = self.report(
            wifi::OP_CONNECT_RESULT,
            &encode_connect_result(0, link.bssid, u32::from(link.frequency)),
        );
        self.signal.raise();
        Ok(())
    }

    /// The built-in `Device::disassociate`: native peer/vdev teardown. The
    /// netdev stays closed afterwards, as built in (the retained radio is
    /// closed by a completed disconnect until a full reset).
    pub(super) async fn disassociate(&self) -> Result<(), WirelessError> {
        // An operator disconnect ends the network block's automatic reuse.
        *PROFILE.lock() = None;
        self.close();
        let mut radio = self.radio.lock().await;
        self.tx.lock().clear();
        if radio.scan_in_progress() {
            radio.fail_station_data();
            self.signal.raise();
            return Err(WirelessError::Busy);
        }
        if radio.station_retired() {
            return Ok(());
        }
        radio.disconnect_station().await.map(|_| ()).map_err(error)
    }

    /// A `CONNECT` that left the BSS to the driver (all-zero BSSID or no
    /// frequency): the strongest matching network of the last scan
    /// (`cfg80211_get_bss` in `cfg80211_sme_get_conn_ies`).
    fn resolve_bss(&self, mut req: AssociateRequest) -> Option<AssociateRequest> {
        if req.bssid != [0; 6] && req.frequency_mhz != 0 {
            return Some(req);
        }
        let scan = self.last_scan.lock();
        let (bssid, frequency) = scan
            .iter()
            .filter(|b| {
                if req.bssid != [0; 6] {
                    b.bssid == req.bssid
                } else {
                    b.ssid == req.ssid
                }
            })
            .max_by_key(|b| b.rssi)
            .map(|b| (b.bssid, b.frequency_mhz))?;
        req.bssid = bssid;
        req.frequency_mhz = frequency;
        req.channel = narf_wireless::association::channel::from_frequency(frequency)
            .map(u32::from)
            .unwrap_or(0);
        Some(req)
    }

    /// The built-in `Device::progress` + `drain`: decode RX, check carrier,
    /// hand queued TX to HTT and deliver admitted Ethernet to the stack.
    /// Returns whether frames moved.
    fn drain(&self) -> bool {
        if self.stopped() {
            return false;
        }
        let Some(mut radio) = self.radio.try_lock() else {
            return false;
        };
        if radio.roc_active() {
            return false;
        }
        let result: Result<(Vec<Vec<u8>>, bool), Error> = (|| {
            if !radio.has_station_data() {
                radio.poll_passive_host_idle()?;
                return Ok((Vec::new(), false));
            }
            let domain = current_domain()?;
            let frames = radio.poll_ethernet_now(&domain)?;
            radio.check_data_policy(&current_domain()?)?;
            if radio.data_permission().is_none() {
                // An established rekey closes DATA, not the carrier.
                return Ok((Vec::new(), false));
            }
            let source = radio.htt.wmi.htc.transport.current_sources();
            let peer = radio.station_link().map(|link| link.bssid);
            super::firmware_source::invoke(source.as_ref(), || {
                self.publish_link(peer, (wifi::REASON_UNSPECIFIED, false))
            })
            .map_err(|_| Error::Failed)?;
            let mut sent = false;
            for _ in 0..TX_BATCH {
                let Some(frame) = self.tx.lock().pop_front() else {
                    break;
                };
                match radio.begin_ethernet(&domain, &frame) {
                    Ok(_) => sent = true,
                    Err(Error::Htt(super::htt_runtime::Error::Busy)) => {
                        self.tx.lock().push_front(frame);
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok((frames, sent))
        })();
        match result {
            Ok((frames, sent)) => {
                let permission = radio.data_permission();
                drop(radio);
                let progressed = sent || !frames.is_empty();
                for mut frame in frames {
                    // The radio lock is released before the stack runs: an
                    // ARP/ND reply may come straight back through TX.
                    if self.stopped() || permission.is_none() {
                        break;
                    }
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
                progressed
            }
            Err(_) => {
                radio.fail_station_data();
                drop(radio);
                self.tx.lock().clear();
                self.close();
                false
            }
        }
    }

    /// The built-in `cleanup_failed_scan`, station subset: a scan whose
    /// public future went away retains its STOP/vdev cleanup here.
    async fn cleanup_failed_scan(&self) -> Result<bool, Error> {
        let Some(mut radio) = self.radio.try_lock() else {
            return Ok(false);
        };
        if !radio.scan_in_progress() {
            if radio.failed_station_pending() {
                self.close();
                radio.retire_station_receive();
                return Err(Error::Failed);
            }
            return Ok(false);
        }
        if self.closed.load(Ordering::Acquire) {
            radio.fail_station_data();
        }
        if !radio.failed_scan_pending() {
            return Ok(false);
        }
        self.close();
        radio.retire_station_receive();
        let quarantine = self.quarantine.clone();
        radio
            .abort_failed_scan(&|| {
                if quarantine.load(Ordering::Acquire) {
                    Err(Error::Failed)
                } else {
                    Ok(())
                }
            })
            .await?;
        Ok(true)
    }

    /// The built-in `flush_management`: send a queued protected SA Query
    /// response (PMF) produced by the drain.
    async fn flush_management(&self) {
        if self.stopped() {
            return;
        }
        let Some(mut radio) = self.radio.try_lock() else {
            return;
        };
        let Ok(domain) = current_domain() else {
            return;
        };
        let validate = || {
            if self.stopped() {
                return Err(Error::Failed);
            }
            Ok(())
        };
        if wmi_runtime::checked_policy(radio.flush_station_management(&domain), &validate)
            .await
            .is_err()
        {
            radio.fail_station_data();
            drop(radio);
            self.close();
        }
    }

    /// The service worker (the built-in NAPI-equivalent loop).
    async fn run(self: Arc<Self>) {
        loop {
            if self.dead.load(Ordering::Acquire) || self.quarantine.load(Ordering::Acquire) {
                return;
            }
            match self.cleanup_failed_scan().await {
                Ok(false) => {}
                Ok(true) => return,
                Err(_) => {
                    super::pci::scan_cleanup_failed(self.radio.clone());
                    return;
                }
            }
            let seen = self.signal.count();
            let progressed = self.drain();
            self.flush_management().await;
            if progressed {
                platform::yield_now().await;
                continue;
            }
            let ms = super::irq::fallback_ms(self.delivered);
            let timer = platform::time::sleep_ns(ms * 1_000_000);
            self.signal.wait(seen, core::pin::pin!(timer)).await;
        }
    }
}

/// Netif TX: the stack hands one Ethernet frame (borrowed for this call).
extern "C" fn tx_callback(_dev: u64, frame: *const u8, len: usize) -> i32 {
    let Some(dev) = netdev() else {
        return -19;
    };
    if frame.is_null() || len < 14 || !dev.up.load(Ordering::Acquire) || dev.stopped() {
        return ENOBUFS;
    }
    // SAFETY: the bridge lends `len` readable bytes for the call.
    let bytes = unsafe { core::slice::from_raw_parts(frame, len) };
    if !admitted(bytes, dev.mac) {
        return ENOBUFS;
    }
    {
        let mut q = dev.tx.lock();
        if q.len() >= TX_QUEUE_MAX {
            return ENOBUFS;
        }
        q.push_back(bytes.to_vec());
    }
    dev.signal.raise();
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
                let was = dev.up.load(Ordering::Acquire);
                let _ = dev.disassociate().await;
                // A disconnect while not associated still completes the
                // host's wait (`close` reported it if carrier was up).
                if !was {
                    let _ = dev.report(
                        wifi::OP_DISCONNECTED,
                        &encode_disconnected(wifi::REASON_DEAUTH_LEAVING, true),
                    );
                }
            });
            0
        }
        // A native scan has no cancellation hook here; the result of an
        // aborted scan is simply discarded by the host.
        wifi::EVENT_SCAN_ABORT => 0,
        _ => -95,
    }
}

async fn scan_and_report(dev: &ModuleNetdev, req: ScanRequest) {
    let status = match dev.scan(req).await {
        Ok(results) => {
            for (bss, ies) in results {
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
        channel: narf_wireless::association::channel::from_frequency(frequency_mhz)
            .map(u32::from)
            .unwrap_or(0),
        security,
        ie,
    })
}

/// `REGISTER_WIPHY` from the radio's channels and capabilities (the
/// built-in `phy_capabilities`/`cipher_suites`, station subset).
fn encode_register_wiphy(
    ifindex: u32,
    mac: [u8; 6],
    frequencies: &[u16],
    ht: bool,
    vht: bool,
) -> Vec<u8> {
    let (mut b2, mut b5) = (Vec::new(), Vec::new());
    for &f in frequencies {
        let Some(ch) = narf_wireless::association::channel::from_frequency(u32::from(f)) else {
            continue;
        };
        let list = if f < 3000 { &mut b2 } else { &mut b5 };
        if list.len() < 64 && !list.contains(&ch) {
            list.push(ch);
        }
    }
    let mut hw = 0u8;
    if ht {
        hw |= 1;
    }
    if vht {
        hw |= 2;
    }
    // The built-in netdev's `cipher_suites`: the station's data cipher.
    let ciphers = [narf_wireless::CIPHER_SUITE_CCMP];
    let bands: Vec<(u32, &Vec<u8>)> = [(2412u32, &b2), (5180, &b5)]
        .into_iter()
        .filter(|(_, list)| !list.is_empty())
        .collect();
    let mut out = Vec::new();
    out.extend_from_slice(&ifindex.to_le_bytes());
    out.extend_from_slice(&mac);
    out.extend_from_slice(&1u32.to_le_bytes()); // STATION
    out.push(hw);
    out.push(ciphers.len() as u8);
    out.push(bands.len() as u8);
    out.push(wifi::FLAG_PSK_OFFLOAD | wifi::FLAG_SAE_OFFLOAD | wifi::FLAG_REPORTS_DISCONNECT);
    out.push(wmi_runtime::MAX_SCAN_SSIDS as u8);
    out.push(0);
    out.extend_from_slice(&wmi_runtime::MAX_SCAN_IE_LEN.to_le_bytes());
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

/// Retire the published station of exactly this radio generation before
/// recovery (the built-in `interface::retire`): carrier off with a
/// `DISCONNECTED` report, no further service. The netdev, session and wiphy
/// stay for the next generation.
pub(super) fn retire(radio: &SharedRadio) {
    let device = {
        let mut current = NETDEV.lock();
        match current.as_ref() {
            Some(d) if Arc::ptr_eq(&d.radio, radio) => current.take(),
            _ => None,
        }
    };
    let Some(device) = device else {
        return;
    };
    device.dead.store(true, Ordering::Release);
    device.publish_link(None, (wifi::REASON_UNSPECIFIED, false));
    device.tx.lock().clear();
    device.signal.raise();
    log(format_args!("station generation retired for recovery"));
}

/// The built-in `replay_retained`: scan for the retained BSS on its
/// channel, then associate with the retained credentials. One attempt; the
/// profile is retained again only by a completed association.
async fn replay(device: Arc<ModuleNetdev>) {
    let Some(profile) = PROFILE.lock().take() else {
        return;
    };
    let Some(request) = profile.request() else {
        return;
    };
    let found = device
        .scan(ScanRequest {
            ssids: alloc::vec![profile.ssid.clone()],
            frequencies_mhz: alloc::vec![profile.frequency_mhz],
            channels: alloc::vec![profile.channel],
            active: false,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: None,
            duration_mandatory: false,
            extra_ies: Vec::new(),
        })
        .await;
    let present = found.is_ok_and(|list| {
        list.iter().any(|(b, _)| {
            b.bssid == profile.bssid
                && b.frequency_mhz == profile.frequency_mhz
                && b.ssid == profile.ssid
        })
    });
    if !present {
        log(format_args!("retained network not found after recovery"));
        return;
    }
    match device.associate(request).await {
        Ok(()) => log(format_args!("reassociated after recovery")),
        Err(e) => log(format_args!("reassociation after recovery failed: {:?}", e)),
    }
}

/// The radio generation's station facts (the built-in `publish`'s
/// `station_publishable`, channel list, capabilities and wake source).
struct Facts {
    mac: [u8; 6],
    frequencies: Vec<u16>,
    ht: bool,
    vht: bool,
    signal: Arc<super::irq::Signal>,
    delivered: bool,
}

async fn facts(radio: &SharedRadio) -> Result<Facts, Error> {
    let r = radio.lock().await;
    let mac = r.station_publishable()?;
    let frequencies = r
        .configured_channels()
        .iter()
        .copied()
        .filter(|f| Permission::station_frequency(*f))
        .collect();
    let (signal, delivered) = r.htt.wmi.htc.transport.interrupt();
    Ok(Facts {
        mac,
        frequencies,
        ht: r.ht_capabilities().is_some() || r.ht40_capabilities().is_some(),
        vht: r.vht_capabilities().is_some(),
        signal,
        delivered,
    })
}

/// Install one generation behind the shell and start its worker.
fn install(
    radio: SharedRadio,
    quarantine: Arc<AtomicBool>,
    shell: (u64, u32),
    facts: Facts,
) -> Arc<ModuleNetdev> {
    let (session, ifindex) = shell;
    let dev = Arc::new(ModuleNetdev {
        radio,
        quarantine,
        mac: facts.mac,
        ifindex,
        session,
        frequencies: facts.frequencies,
        bssid: AtomicU64::new(0),
        up: AtomicBool::new(false),
        closed: AtomicBool::new(false),
        dead: AtomicBool::new(false),
        joining: AtomicBool::new(false),
        tx: IrqSafeSpinLock::new(VecDeque::new()),
        last_scan: IrqSafeSpinLock::new(Vec::new()),
        signal: facts.signal,
        delivered: facts.delivered,
    });
    *NETDEV.lock() = Some(dev.clone());
    platform::spawn(dev.clone().run());
    dev
}

/// Publish the radio's station (the built-in `interface::wait_publish`):
/// the regulatory domain, the `WIFI` session, the netdev, the wiphy and the
/// service worker. The radio stays receive-only until a `CONNECT`. A
/// recovered generation rebinds the existing netdev and wiphy instead.
pub(super) async fn wait_publish(
    radio: SharedRadio,
    quarantine: Arc<AtomicBool>,
) -> Result<(), Error> {
    if quarantine.load(Ordering::Acquire) || netdev().is_some() {
        return Err(Error::Failed);
    }
    if let Err(e) = platform::reg::ensure_domain() {
        log(format_args!(
            "no regulatory domain ({:?}); station not published",
            e
        ));
        return Err(Error::Unsupported);
    }
    let facts = facts(&radio).await?;
    let shell = SHELL.lock().as_ref().map(|s| (s.session, s.ifindex, s.mac));
    if let Some((session, ifindex, mac)) = shell {
        // `ieee80211_reconfig`: the same netdev and wiphy, a fresh radio.
        if mac != facts.mac {
            log(format_args!(
                "recovered generation changed its MAC; not rebound"
            ));
            return Err(Error::Failed);
        }
        if quarantine.load(Ordering::Acquire) {
            return Err(Error::Failed);
        }
        let dev = install(radio, quarantine, (session, ifindex), facts);
        log(format_args!("station rebound to the recovered generation"));
        if PROFILE.lock().is_some() {
            platform::spawn(replay(dev));
        }
        return Ok(());
    }
    let mac = facts.mac;
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
        return Err(Error::Unsupported);
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
        return Err(Error::Unsupported);
    }
    let wiphy = encode_register_wiphy(ifindex, mac, &facts.frequencies, facts.ht, facts.vht);
    let channels = facts.frequencies.len();
    *SHELL.lock() = Some(Shell {
        session,
        ifindex,
        mac,
    });
    let dev = install(radio, quarantine, (session, ifindex), facts);
    let rc = dev.report(wifi::OP_REGISTER_WIPHY, &wiphy);
    if rc != 0 {
        log(format_args!("wiphy registration refused ({rc})"));
    }
    log(format_args!(
        "wlan (ifindex {ifindex}) {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, {channels} channels",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
    ));
    Ok(())
}
