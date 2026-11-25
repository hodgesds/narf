//! The module build's Gen2 (AX200/AX201) station netdev and wiphy.
//!
//! Built in, `mvm_device::Device` publishes the retained API77 MVM owner
//! ([`Owner`]) as a `WirelessNetIface` with frame rings, AP/P2P roles,
//! scheduled scan, WoWLAN and system PM. This is its station subset, over
//! the same owner and the same publication fences, through the netif bridge
//! and the `WIFI` family host (version 2):
//!
//! - **scan** — `Operation::Scan`: passive (`station_scan`) or, when asked,
//!   active at the signed scan-power program (`active_scan_using`), then the
//!   same post-scan policy re-check and SSID filter;
//! - **connect** — `Operation::Join`: the 10 s scan-freshness bound, the
//!   station offer, the policy restriction, the signed platform-power
//!   program (`Environment::native`'s selection: feature, nested-BA, then
//!   station program), `station_join` with the native WPA2-PSK four-way owner
//!   or host SAE plus PMF, then the controlled-port publication fence;
//! - **service** — `step_native`'s station branch: idle polling, RX with the
//!   rekey hand-off (`Operation::Maintain`), beacon/data liveness, TX
//!   publication with the BA-pipeline / A-MSDU batching (`Operation::Transmit`);
//! - **disconnect** — `Operation::Close`;
//! - **recovery** — a failed owner is restarted (`Operation::Recover`)
//!   before the next scan.
//!
//! Every operation runs under `begin`'s fence: the executable/PCI source,
//! the current regulatory domain's channel policy and, for maintenance and
//! TX, the current power qualification. Signed power programs are read
//! through the module's firmware loader with their verified signer, as built
//! in. Not carried: AP/P2P, scheduled scan, WoWLAN/D3 and system PM.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::{poll_fn, Future};
use core::pin::pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::Poll;

use narf_wireless::reg::RegulatoryDomain;
use narf_wireless::scan::BssSecurity;
use narf_wireless::{BssInfo, ScanRequest, WirelessError};
use zeroize::Zeroizing;

use super::super::connection::AuthMethod;
use super::super::mvm_boot::{self, Credential, LegacyReceive, Owner, Phase, PowerEmission};
use super::super::mvm_publication::{Power, Publication, Source};
use super::super::runtime::Hardware;
use super::firmware_asset::{self, Asset};
use super::kernel::narf_capabilities::{Cap, Read};
use super::kernel::narf_firmware::{self, FirmwareBlob};
use super::kernel::narf_lib::mutex::Mutex;
use super::kernel::narf_lib::sync::IrqSafeSpinLock;
use super::kernel::narf_time;
use super::netdev::{self, ffi, wifi, ConnectRequest};

const ENOBUFS: i32 = -105;
const EBUSY: i32 = -16;
const EIO: i32 = -5;
const EINVAL: i32 = -22;
const ENODEV: i32 = -19;
const EOPNOTSUPP: i32 = -95;
/// Frames queued between the stack and the station.
const TX_QUEUE_MAX: usize = 512;
/// The built-in scan-freshness bound for a join (10 s).
const SCAN_FRESH_NS: u64 = 10_000_000_000;
/// How often the service re-reads the kernel's regulatory domain.
const REGULATORY_REFRESH_NS: u64 = 1_000_000_000;
/// The largest signed power program (`mvm_device`'s loads).
const POWER_RECORD_MAX: usize = 64;

/// `Environment::native().policy`.
fn policy() -> Result<RegulatoryDomain, &'static str> {
    super::super::reg_source::get_domain().ok_or("MVM authenticated policy unavailable")
}

/// `Environment::native().nonce`.
fn nonce() -> Result<[u8; 32], &'static str> {
    super::super::security::fresh_nonce()
}

fn load_signed(name: &str) -> Result<Asset, narf_firmware::FirmwareError> {
    let authority = narf_firmware::trusted_loader_authority()
        .and_then(|cap| cap.derive().ok())
        .ok_or(narf_firmware::FirmwareError::AuthorityRevoked)?;
    firmware_asset::load(&authority, name, POWER_RECORD_MAX, true)
}

/// `Environment::native().scan_power`.
fn scan_power(owner: &mut Owner, channels: &[u8]) -> Result<(Asset, [u8; 32]), &'static str> {
    let request = owner.scan_power_request(channels)?;
    let source = load_signed(&request.name)
        .map_err(|_| "MVM signed active-scan power source unavailable")?;
    Ok((source, request.binding))
}

/// `Environment::native().power`: the widest signed program present — a
/// feature program, else the nested-BA program, else the station program.
/// An absent optional program falls back; an invalid one never downgrades.
fn station_power(owner: &mut Owner) -> Result<(Asset, [u8; 32]), &'static str> {
    for bits in owner.feature_offers() {
        let request = owner.transmit_power_request_for(PowerEmission::Features(bits))?;
        match load_signed(&request.name) {
            Ok(source) => {
                owner.select_feature_power(&source, request.binding, bits)?;
                return Ok((source, request.binding));
            }
            Err(narf_firmware::FirmwareError::NotFound) => {}
            Err(_) => return Err("MVM signed feature power source invalid"),
        }
    }
    if owner.nested_ba_offer() {
        let request = owner.transmit_power_request_for(PowerEmission::Ht20NestedBa)?;
        match load_signed(&request.name) {
            Ok(source) => {
                owner.select_nested_power(&source, request.binding)?;
                return Ok((source, request.binding));
            }
            Err(narf_firmware::FirmwareError::NotFound) => {}
            Err(_) => return Err("MVM signed nested BA power source invalid"),
        }
    }
    let request = owner.station_power_request()?;
    let source =
        load_signed(&request.name).map_err(|_| "MVM signed platform power source unavailable")?;
    Ok((source, request.binding))
}

/// `mvm_device::admitted`, for frames without offload metadata.
fn admitted(bytes: &[u8], mac: [u8; 6]) -> bool {
    (14..=1514).contains(&bytes.len())
        && bytes[6..12] == mac
        && u16::from_be_bytes([bytes[12], bytes[13]]) >= 0x600
        && !matches!(
            u16::from_be_bytes([bytes[12], bytes[13]]),
            0x888e | 0x80f3 | 0x8137
        )
}

/// `mvm_device::channel_frequency`.
fn channel_frequency(channel: u8) -> u32 {
    if channel == 14 {
        2484
    } else if channel <= 13 {
        2407 + u32::from(channel) * 5
    } else {
        5000 + u32::from(channel) * 5
    }
}

struct State {
    owner: Box<Owner>,
    /// The next frame to publish.
    pending: Option<Vec<u8>>,
    /// When the last scan started (its observations' age bound).
    scan_time: Option<u64>,
}

/// One bound Gen2 radio (module build).
struct Radio {
    mac: [u8; 6],
    ifindex: u32,
    session: u64,
    channels: Vec<u8>,
    wpa2: bool,
    sae: bool,
    ht20: bool,
    vht: bool,
    he: bool,
    irq: Option<u8>,
    firmware: Cap<FirmwareBlob, Read>,
    source: Source,
    state: Mutex<State>,
    /// The owner failed: restart before the next scan.
    terminal: AtomicBool,
    /// A close is in progress (`Owner::bind_station_stop`).
    stopping: Arc<AtomicBool>,
    /// Carrier and the controlled port.
    up: AtomicBool,
    port: AtomicBool,
    /// bit 56 = associated, low 48 bits = BSSID (LE), as built in.
    bssid: AtomicU64,
    generation: Arc<AtomicU64>,
    /// The controlled port's publication authority.
    fence: IrqSafeSpinLock<Option<Publication>>,
    tx: IrqSafeSpinLock<VecDeque<Vec<u8>>>,
    last_scan: IrqSafeSpinLock<Vec<BssInfo>>,
}

static RADIO: IrqSafeSpinLock<Option<Arc<Radio>>> = IrqSafeSpinLock::new(None);

fn radio() -> Option<Arc<Radio>> {
    RADIO.lock().clone()
}

/// How an operation is fenced (`mvm_device::begin`).
#[derive(Clone, Copy)]
enum Fence<'a> {
    /// Close: only the executable/PCI source.
    Source,
    /// Scan/join: the source and the current channel policy (`transmit`:
    /// the join's host TX power must exist on the channel).
    Policy { channels: &'a [u8], transmit: bool },
    /// Maintenance/TX: the source, and the power qualification of the port.
    Qualified,
}

impl Radio {
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

    /// `retire_port_locked`: a new generation closes the old port.
    fn retire_port(&self) {
        match self.generation.load(Ordering::Acquire).checked_add(1) {
            Some(next) => self.generation.store(next, Ordering::Release),
            None => self.terminal.store(true, Ordering::Release),
        }
        self.port.store(false, Ordering::Release);
    }

    /// `down_locked`: carrier off. `true` when carrier was up.
    fn down(&self, terminal: bool) -> bool {
        self.retire_port();
        if terminal {
            self.terminal.store(true, Ordering::Release);
        }
        self.bssid.store(0, Ordering::Release);
        *self.fence.lock() = None;
        self.tx.lock().clear();
        self.up.swap(false, Ordering::AcqRel)
    }

    /// `admit_port`: open the controlled port under the power fence.
    fn admit_port(&self, owner: &mut Owner, bssid: [u8; 6]) -> Result<(), &'static str> {
        let power = owner.station_power_fence(&policy()?)?;
        if self.terminal.load(Ordering::Acquire) || self.stopping.load(Ordering::Acquire) {
            return Err("MVM station publication cancelled by close");
        }
        let generation = self
            .generation
            .load(Ordering::Acquire)
            .checked_add(1)
            .ok_or("MVM publication generation exhausted")?;
        self.generation.store(generation, Ordering::Release);
        let authority = Publication {
            source: self.source.clone(),
            power: Arc::new(Power::Station(power)),
            generation: (self.generation.clone(), generation),
        };
        authority.invoke(&policy()?, || {
            *self.fence.lock() = Some(authority.clone());
            self.bssid.store(
                u64::from_le_bytes([
                    bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], 0, 1,
                ]),
                Ordering::Release,
            );
            self.up.store(true, Ordering::Release);
            self.port.store(true, Ordering::Release);
            Ok(())
        })
    }

    /// Poll `future` under `fence` (`mvm_device::begin`'s wrapper).
    async fn fenced<T>(
        &self,
        fence: Fence<'_>,
        qualification: Option<Publication>,
        future: impl Future<Output = Result<T, &'static str>>,
    ) -> Result<T, &'static str> {
        let mut future = pin!(future);
        poll_fn(|cx| {
            match self.source.invoke(|| {
                let domain = match fence {
                    Fence::Source => return Ok(future.as_mut().poll(cx)),
                    Fence::Policy { channels, transmit } => {
                        let domain = policy()?;
                        if channels.iter().any(|&channel| {
                            if transmit {
                                super::super::connection::host_channel_power(&domain, channel, true)
                                    .is_none()
                            } else {
                                !mvm_boot::passive_channel(&domain, channel)
                            }
                        }) {
                            return Err("MVM live operation channel policy revoked");
                        }
                        domain
                    }
                    Fence::Qualified => policy()?,
                };
                match qualification
                    .as_ref()
                    .filter(|_| !self.stopping.load(Ordering::Acquire))
                {
                    Some(qualification) => qualification
                        .power
                        .invoke(&domain, || Ok(future.as_mut().poll(cx))),
                    None => Ok(future.as_mut().poll(cx)),
                }
            }) {
                Ok(result) => result,
                Err(error) => Poll::Ready(Err(error)),
            }
        })
        .await
    }

    /// The common failure tail of an operation (`begin`'s): a scan the fence
    /// interrupted is stopped first; any failure outside a clean Configured
    /// owner is terminal for the station.
    async fn settle(&self, state: &mut State, failed: bool) -> bool {
        if !failed {
            return false;
        }
        if state.owner.phase() == Phase::Scanning {
            state.owner.station_fail();
            let _ = state.owner.suspend_transport().await;
        }
        if state.owner.phase() != Phase::Configured || self.source.invoke(|| Ok(())).is_err() {
            state.owner.station_fail();
            state.pending = None;
            return self.down(true);
        }
        false
    }

    /// `Operation::Recover` (`recover_failed`): restart a failed owner,
    /// polled under the boot (non-master) authority.
    async fn recover(&self, state: &mut State) -> Result<(), WirelessError> {
        if !self.terminal.load(Ordering::Acquire) {
            return Ok(());
        }
        if !state.owner.station_failed() {
            return Err(WirelessError::HardwareError);
        }
        state.pending = None;
        state.scan_time = None;
        self.tx.lock().clear();
        let boot = state.owner.station_source(self.firmware, false);
        let result = {
            let mut future = pin!(state.owner.recover());
            poll_fn(|cx| match boot.invoke(|| Ok(future.as_mut().poll(cx))) {
                Ok(result) => result,
                Err(error) => Poll::Ready(Err(error)),
            })
            .await
        };
        if result.is_ok()
            && state.owner.phase() == Phase::Configured
            && !state.owner.station_failed()
            && self.source.invoke(|| Ok(())).is_ok()
            && !self.stopping.load(Ordering::Acquire)
        {
            self.terminal.store(false, Ordering::Release);
            return Ok(());
        }
        Err(WirelessError::HardwareError)
    }

    /// `WirelessNetIface::scan` + `Operation::Scan`.
    async fn scan(&self, request: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        if request.random_mac.is_some()
            || request.colocated_6ghz
            || request.duration_mandatory
            || !request.extra_ies.is_empty()
            || request.ssids.len() > 20
            || request.ssids.iter().any(|s| s.len() > 32)
            || request.duration_tu.is_some()
        {
            return Err(WirelessError::NotSupported);
        }
        let channels = if !request.frequencies_mhz.is_empty() {
            let mut channels = Vec::new();
            for frequency in &request.frequencies_mhz {
                let ch = self
                    .channels
                    .iter()
                    .copied()
                    .find(|&ch| channel_frequency(ch) == *frequency)
                    .ok_or(WirelessError::InvalidArgs)?;
                if channels.contains(&ch) {
                    return Err(WirelessError::InvalidArgs);
                }
                channels.push(ch);
            }
            channels
        } else {
            self.channels.clone()
        };
        let mut state = self.state.try_lock().ok_or(WirelessError::Busy)?;
        self.recover(&mut state).await?;
        if self.stopping.load(Ordering::Acquire) || state.owner.phase() != Phase::Configured {
            return Err(WirelessError::Busy);
        }
        let started = narf_time::now_cycles();
        state.scan_time = None;
        let ssids = request.ssids;
        let active = request.active;
        let result = {
            let State { owner, .. } = &mut *state;
            let fence = Fence::Policy {
                channels: &channels,
                transmit: false,
            };
            self.fenced(fence, None, async {
                let mut result = if active {
                    let (source, binding) = scan_power(owner, &channels)?;
                    owner
                        .active_scan_using(&channels, &ssids, source, binding, policy)
                        .await?
                } else {
                    owner.station_scan(&channels, &policy()?).await?
                };
                let current = policy()?;
                if channels
                    .iter()
                    .any(|&ch| !mvm_boot::passive_channel(&current, ch))
                {
                    return Err("MVM scan policy tightened before result publication");
                }
                result.retain(|bss| {
                    ssids.is_empty() || ssids.iter().any(Vec::is_empty) || ssids.contains(&bss.ssid)
                });
                Ok(result)
            })
            .await
        };
        let lost = self.settle(&mut state, result.is_err()).await;
        drop(state);
        if lost {
            self.report_loss();
        }
        match result {
            Ok(result) => {
                if let Some(mut state) = self.state.try_lock() {
                    state.scan_time = Some(started);
                }
                Ok(result)
            }
            Err(error) => {
                netdev::log(format_args!("scan failed: {error}"));
                Err(match error {
                    "MVM control busy" | "MVM station is closing" => WirelessError::Busy,
                    _ => WirelessError::HardwareError,
                })
            }
        }
    }

    /// `WirelessNetIface::associate` + `Operation::Join`.
    async fn associate(&self, request: ConnectRequest) -> Result<[u8; 6], WirelessError> {
        let channel = self
            .channels
            .iter()
            .copied()
            .find(|&ch| channel_frequency(ch) == request.frequency_mhz)
            .ok_or(WirelessError::InvalidArgs)?;
        if request.ssid.is_empty()
            || request.ssid.len() > 32
            || request.bssid == [0; 6]
            || request.bssid[0] & 1 != 0
        {
            return Err(WirelessError::InvalidArgs);
        }
        let credential = match request.auth {
            AuthMethod::Open => Credential::Open,
            AuthMethod::Wpa2Psk(psk) if self.wpa2 => Credential::Psk(Zeroizing::new(psk)),
            AuthMethod::Wpa3Sae { password } if self.sae => {
                Credential::Sae(Zeroizing::new(password))
            }
            _ => return Err(WirelessError::NotSupported),
        };
        let mut state = self.state.try_lock().ok_or(WirelessError::Busy)?;
        if self.terminal.load(Ordering::Acquire)
            || self.stopping.load(Ordering::Acquire)
            || state.owner.phase() != Phase::Configured
        {
            return Err(WirelessError::Busy);
        }
        let bssid = request.bssid;
        let ssid = request.ssid;
        let elements = request.ie;
        let channels = [channel];
        let result = {
            let State {
                owner, scan_time, ..
            } = &mut *state;
            let fresh = scan_time.is_some_and(|time| {
                narf_time::now_cycles().wrapping_sub(time)
                    <= narf_time::wall::ns_to_cycles(SCAN_FRESH_NS)
            });
            let fence = Fence::Policy {
                channels: &channels,
                transmit: true,
            };
            self.fenced(fence, None, async {
                if !fresh {
                    return Err("MVM scan observation expired");
                }
                owner.select_station_offer(bssid, &ssid, channel, &elements, credential.mode())?;
                owner.restrict_offer(&policy()?);
                let (source, binding) = station_power(owner)?;
                crate::future_heap::build(|| {
                    owner.station_join(
                        bssid,
                        &ssid,
                        channel,
                        &elements,
                        credential,
                        source,
                        binding,
                        self.stopping.clone(),
                        policy,
                        nonce,
                    )
                })
                .await
            })
            .await
            .and_then(|()| {
                if self.stopping.load(Ordering::Acquire) {
                    return Ok(());
                }
                self.admit_port(owner, bssid)
            })
        };
        let lost = self.settle(&mut state, result.is_err()).await;
        drop(state);
        if lost {
            self.report_loss();
        }
        match result {
            Ok(()) if self.link_up() => Ok(bssid),
            Ok(()) => Err(WirelessError::Busy),
            Err(error) => {
                netdev::log(format_args!("association failed: {error}"));
                Err(WirelessError::HardwareError)
            }
        }
    }

    /// `WirelessNetIface::disassociate` + `Operation::Close`.
    async fn disassociate(&self) -> Result<(), WirelessError> {
        self.stopping.store(true, Ordering::Release);
        let _ = self.down(false);
        let mut state = self.state.lock().await;
        state.pending = None;
        let result = {
            let State { owner, .. } = &mut *state;
            self.fenced(Fence::Source, None, owner.station_close(policy))
                .await
        };
        let _ = self.settle(&mut state, result.is_err()).await;
        self.stopping.store(false, Ordering::Release);
        result.map_err(|_| WirelessError::HardwareError)
    }

    /// One `step_native` station pass with its follow-up operation.
    /// Returns frames for the stack, whether carrier was lost, and whether
    /// more work is ready.
    async fn step(&self, state: &mut State) -> (Vec<Vec<u8>>, bool, bool) {
        if self.terminal.load(Ordering::Acquire) || self.stopping.load(Ordering::Acquire) {
            return (Vec::new(), false, false);
        }
        let result: Result<(Vec<Vec<u8>>, bool, bool), &'static str> = (|| {
            self.source.invoke(|| Ok(()))?;
            if state.owner.phase() != Phase::DataPrepared {
                state.owner.station_poll_idle()?;
                return Ok((Vec::new(), false, false));
            }
            let mut output = Vec::new();
            for _ in 0..64 {
                match state.owner.station_receive(policy)? {
                    Some(LegacyReceive::Ethernet(frame)) => output.push(frame),
                    Some(LegacyReceive::Checked(frame, _meta)) => output.push(frame),
                    Some(LegacyReceive::Eapol(_)) => {
                        return Err("MVM secured station lost its native RSNA owner")
                    }
                    None => break,
                }
            }
            if state.owner.station_needs_security() {
                for frame in output.into_iter().rev() {
                    state.owner.station_defer_packet(frame);
                }
                self.retire_port();
                return Ok((Vec::new(), true, false));
            }
            if state.owner.station_expired() {
                return Err("MVM current AP beacon/data liveness expired");
            }
            let authority = Publication {
                source: self.source.clone(),
                power: Arc::new(Power::Station(state.owner.station_power_fence(&policy()?)?)),
                generation: (
                    self.generation.clone(),
                    self.generation.load(Ordering::Acquire),
                ),
            };
            let mut delivered = Vec::new();
            for frame in output {
                authority.invoke(&policy()?, || {
                    if !self.port.load(Ordering::Acquire) || self.stopping.load(Ordering::Acquire) {
                        return Err("MVM RX publication closed");
                    }
                    Ok(())
                })?;
                delivered.push(frame);
            }
            if state.pending.is_none() {
                let mut tx = self.tx.lock();
                while let Some(frame) = tx.pop_front() {
                    if admitted(&frame, self.mac) {
                        state.pending = Some(frame);
                        break;
                    }
                }
            }
            Ok((delivered, false, state.pending.is_some()))
        })();
        let (output, maintenance, transmit) = match result {
            Ok(step) => step,
            Err(_) => {
                state.owner.station_fail();
                return (Vec::new(), self.down(true), false);
            }
        };
        if maintenance {
            // `Operation::Maintain`: the native rekey, then the port reopens.
            let qualification = self.fence.lock().clone();
            let result = {
                let State { owner, .. } = &mut *state;
                self.fenced(
                    Fence::Qualified,
                    qualification,
                    crate::future_heap::build(|| owner.station_security(nonce, policy)),
                )
                .await
                .and_then(|()| {
                    if owner.phase() != Phase::DataPrepared {
                        return Ok(());
                    }
                    let bssid = owner
                        .prepared_legacy_data()
                        .ok_or("MVM terminal data identity missing")?
                        .bssid;
                    self.admit_port(owner, bssid)
                })
            };
            let lost = self.settle(state, result.is_err()).await;
            return (Vec::new(), lost, result.is_ok());
        }
        if transmit {
            let qualification = self.fence.lock().clone();
            let result = self.transmit(state, qualification).await;
            let lost = self.settle(state, result.is_err()).await;
            return (output, lost, result.is_ok());
        }
        (output, false, false)
    }

    /// `Operation::Transmit`: the pending frame, batched with queued frames
    /// of the same TID on the BA pipeline or as an A-MSDU.
    async fn transmit(
        &self,
        state: &mut State,
        qualification: Option<Publication>,
    ) -> Result<(), &'static str> {
        let State { owner, pending, .. } = state;
        let frame = pending.take().ok_or("MVM pending Ethernet missing")?;
        if self.stopping.load(Ordering::Acquire) {
            return Err("MVM data stopped before native publication");
        }
        let tid = owner.data_tid(&frame);
        let amsdu = owner.station_can_amsdu_batch(tid);
        if (owner.station_can_pipeline() && tid == 0) || amsdu {
            let mut packets = alloc::vec![(frame, 0u32)];
            {
                let mut tx = self.tx.lock();
                while packets.len() < 8 {
                    let Some(next) = tx.pop_front() else {
                        break;
                    };
                    if !admitted(&next, self.mac) {
                        continue;
                    }
                    if owner.data_tid(&next) != tid {
                        // Keep order within this TID: it is the next single send.
                        *pending = Some(next);
                        break;
                    }
                    packets.push((next, 0));
                }
            }
            if amsdu {
                self.fenced(
                    Fence::Qualified,
                    qualification,
                    owner.transmit_amsdu_batch_using(&packets, policy),
                )
                .await
            } else {
                self.fenced(
                    Fence::Qualified,
                    qualification,
                    owner.transmit_data_batch_using(&packets, policy),
                )
                .await
            }
        } else {
            self.fenced(
                Fence::Qualified,
                qualification,
                owner.station_send(&frame, 0, policy),
            )
            .await
        }
    }

    fn deliver(&self, frames: Vec<Vec<u8>>) {
        let authority = self.fence.lock().clone();
        for mut frame in frames {
            let Some(authority) = authority.as_ref().filter(|a| a.current()) else {
                return;
            };
            let open = policy().and_then(|domain| {
                authority.invoke(&domain, || {
                    if self.terminal.load(Ordering::Acquire)
                        || self.stopping.load(Ordering::Acquire)
                        || !self.port.load(Ordering::Acquire)
                    {
                        return Err("MVM stack RX closed");
                    }
                    Ok(())
                })
            });
            if open.is_err() {
                if self.down(true) {
                    self.report_loss();
                }
                return;
            }
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

    /// Unsolicited carrier loss (`notify_disconnect(name, 1, false)`).
    fn report_loss(&self) {
        let _ = self.report(
            wifi::OP_DISCONNECTED,
            &netdev::encode_disconnected(wifi::REASON_UNSPECIFIED, false),
        );
    }

    /// The radio's service task (`mvm_device::pump`).
    async fn service(self: Arc<Self>) {
        let mut refreshed = narf_time::now_cycles();
        loop {
            let now = narf_time::now_cycles();
            if now.wrapping_sub(refreshed) >= narf_time::wall::ns_to_cycles(REGULATORY_REFRESH_NS) {
                super::regulatory::refresh();
                refreshed = now;
            }
            let activity = super::super::iwl_msix::Activity::new(self.irq, 20);
            let (output, lost, progress) = match self.state.try_lock() {
                Some(mut state) => self.step(&mut state).await,
                None => (Vec::new(), false, false),
            };
            self.deliver(output);
            if lost {
                self.report_loss();
            }
            if progress {
                narf_module_rt::time::yield_now().await;
                continue;
            }
            activity.await;
        }
    }
}

/// Netif TX: one Ethernet frame (borrowed for this call).
extern "C" fn tx_callback(_dev: u64, frame: *const u8, len: usize) -> i32 {
    let Some(radio) = radio() else {
        return ENODEV;
    };
    if frame.is_null() || len < 14 || !radio.port.load(Ordering::Acquire) {
        return ENOBUFS;
    }
    // SAFETY: the bridge lends `len` readable bytes for the call.
    let bytes = unsafe { core::slice::from_raw_parts(frame, len) }.to_vec();
    if !admitted(&bytes, radio.mac) {
        return EINVAL;
    }
    let mut queue = radio.tx.lock();
    if queue.len() >= TX_QUEUE_MAX {
        return ENOBUFS;
    }
    queue.push_back(bytes);
    0
}

/// Family-host events for a Gen2 radio (dispatched from `netdev`'s callback,
/// one session per device).
pub(super) fn event_callback(_dev: u64, event: u32, payload: *const u8, len: usize) -> i32 {
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
            let Some(request) = netdev::decode_scan_request(&bytes) else {
                return EINVAL;
            };
            let _ = super::EXEC.spawn(async move {
                let status = match radio.scan(request).await {
                    Ok(results) => {
                        *radio.last_scan.lock() = results.clone();
                        let ies: Vec<Vec<u8>> = {
                            let state = radio.state.lock().await;
                            results
                                .iter()
                                .map(|bss| {
                                    state
                                        .owner
                                        .station_information(bss.bssid)
                                        .unwrap_or_default()
                                })
                                .collect()
                        };
                        for (bss, ies) in results.into_iter().zip(ies) {
                            let _ = radio.report(
                                wifi::OP_SCAN_RESULT,
                                &netdev::encode_scan_result(&bss, &ies),
                            );
                        }
                        0i32
                    }
                    Err(WirelessError::Busy) => EBUSY,
                    Err(WirelessError::InvalidArgs) => EINVAL,
                    Err(WirelessError::NotSupported) => EOPNOTSUPP,
                    Err(_) => EIO,
                };
                let _ = radio.report(wifi::OP_SCAN_DONE, &status.to_le_bytes());
            });
            0
        }
        wifi::EVENT_CONNECT => {
            let Some(request) = netdev::decode_connect(&bytes) else {
                return EINVAL;
            };
            let _ = super::EXEC.spawn(async move {
                let (bssid, frequency) = (request.bssid, request.frequency_mhz);
                let result = match resolve_bss(&radio, request) {
                    Some(request) => {
                        let frequency = request.frequency_mhz;
                        radio
                            .associate(request)
                            .await
                            .map(|bssid| (bssid, frequency))
                    }
                    None => Err(WirelessError::InvalidArgs),
                };
                let (status, bssid, frequency) = match result {
                    Ok((bssid, frequency)) => (0, bssid, frequency),
                    Err(error) => {
                        netdev::log(format_args!("connect failed: {:?}", error));
                        (wifi::STATUS_UNSPECIFIED_FAILURE, bssid, frequency)
                    }
                };
                let _ = radio.report(
                    wifi::OP_CONNECT_RESULT,
                    &netdev::encode_connect_result(status, bssid, frequency),
                );
            });
            0
        }
        wifi::EVENT_DISCONNECT => {
            let _ = super::EXEC.spawn(async move {
                if radio.disassociate().await.is_err() {
                    netdev::log(format_args!("disconnect failed the station"));
                }
                let _ = radio.report(
                    wifi::OP_DISCONNECTED,
                    &netdev::encode_disconnected(wifi::REASON_DEAUTH_LEAVING, true),
                );
            });
            0
        }
        // The MVM scan owner has no host abort; the host discards results.
        wifi::EVENT_SCAN_ABORT => 0,
        _ => EOPNOTSUPP,
    }
}

/// A `CONNECT` without a BSSID: the strongest matching network of the last
/// scan.
fn resolve_bss(radio: &Radio, mut request: ConnectRequest) -> Option<ConnectRequest> {
    if request.bssid != [0; 6] && request.frequency_mhz != 0 {
        return Some(request);
    }
    let scan = radio.last_scan.lock();
    let bss = scan
        .iter()
        .filter(|bss| {
            bss.ssid == request.ssid
                && (request.bssid == [0; 6] || bss.bssid == request.bssid)
                && match request.auth {
                    AuthMethod::Open => matches!(bss.security, BssSecurity::Open),
                    _ => matches!(bss.security, BssSecurity::Wpa2 | BssSecurity::Wpa3),
                }
        })
        .max_by_key(|bss| bss.rssi)?;
    request.bssid = bss.bssid;
    request.frequency_mhz = bss.frequency_mhz;
    Some(request)
}

/// `REGISTER_WIPHY` for the Gen2 station (`mvm_device::get_wireless_info`,
/// station subset): 2.4/5 GHz NVM channels, HT/VHT/HE, CCMP, and the
/// in-driver SME the owner supports.
fn encode_register_wiphy(radio: &Radio) -> Vec<u8> {
    let (mut b2, mut b5) = (Vec::new(), Vec::new());
    for &ch in &radio.channels {
        let list = if ch <= 14 { &mut b2 } else { &mut b5 };
        if list.len() < wifi::MAX_CHANNELS_PER_BAND && !list.contains(&ch) {
            list.push(ch);
        }
    }
    let hw = u8::from(radio.ht20) | u8::from(radio.vht) << 1 | u8::from(radio.he) << 2;
    let mut flags = wifi::FLAG_REPORTS_DISCONNECT;
    if radio.wpa2 {
        flags |= wifi::FLAG_PSK_OFFLOAD;
    }
    if radio.sae {
        flags |= wifi::FLAG_SAE_OFFLOAD;
    }
    let ciphers = [narf_wireless::CIPHER_SUITE_CCMP];
    let bands: Vec<(u32, &Vec<u8>)> = [(2412u32, &b2), (5180, &b5)]
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
    out.push(flags);
    out.push(wifi::MAX_SCAN_SSIDS);
    out.push(0);
    // Built in the MVM scan refuses probe IEs (`extra_ies`).
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

/// `mvm_device::Device::initialize` + `configured` + publication: boot the
/// owner (firmware, NVM, runtime defaults) under the boot authority, then
/// register the netdev and wiphy and start the service.
pub(crate) async fn start(
    session: u64,
    hardware: Hardware,
    firmware: Asset,
) -> Result<(), &'static str> {
    let mut owner = Box::new(Owner::new(hardware, &firmware.bytes)?);
    let boot = owner.station_source(firmware.cap, false);
    {
        let mut future = pin!(owner.initialize());
        poll_fn(|cx| match boot.invoke(|| Ok(future.as_mut().poll(cx))) {
            Ok(result) => result,
            Err(error) => Poll::Ready(Err(error)),
        })
        .await?;
    }
    let source = owner.station_source(firmware.cap, true);
    source.invoke(|| Ok(()))?;
    if owner.phase() != Phase::Configured || owner.station_failed() {
        return Err("MVM native configured owner missing");
    }
    let (mac, nvm) = owner.identity().ok_or("MVM native identity missing")?;
    let channels = nvm.channels.clone();
    let vht_nvm = nvm.phy.vht;
    let irq = owner.station_irq();
    let wpa2 = owner.station_wpa2_supported();
    let sae = owner.station_sae_supported();
    let ht20 = owner.supports_native_ht20();
    let vht = ht20 && vht_nvm;
    let he = owner.supports_native_he_contract();
    let stopping = Arc::new(AtomicBool::new(false));
    owner.bind_station_stop(stopping.clone());
    netdev::log(format_args!(
        "Gen2 firmware up: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, {} channels, WPA2 {wpa2} \
         SAE {sae} HT20 {ht20} VHT {vht} HE {he}",
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5],
        channels.len(),
    ));
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
        return Err("netdev registration refused");
    }
    let radio = Arc::new(Radio {
        mac,
        ifindex,
        session,
        channels,
        wpa2,
        sae,
        ht20,
        vht,
        he,
        irq,
        firmware: firmware.cap,
        source,
        state: Mutex::new(State {
            owner,
            pending: None,
            scan_time: None,
        }),
        terminal: AtomicBool::new(false),
        stopping,
        up: AtomicBool::new(false),
        port: AtomicBool::new(false),
        bssid: AtomicU64::new(0),
        generation: Arc::new(AtomicU64::new(0)),
        fence: IrqSafeSpinLock::new(None),
        tx: IrqSafeSpinLock::new(VecDeque::new()),
        last_scan: IrqSafeSpinLock::new(Vec::new()),
    });
    let rc = radio.report(wifi::OP_REGISTER_WIPHY, &encode_register_wiphy(&radio));
    if rc != 0 {
        netdev::log(format_args!("wiphy registration refused ({rc})"));
    } else {
        netdev::log(format_args!(
            "wlan (ifindex {ifindex}) up (Gen2 MVM station)"
        ));
    }
    *RADIO.lock() = Some(radio.clone());
    let _ = super::EXEC.spawn(radio.service());
    Ok(())
}
