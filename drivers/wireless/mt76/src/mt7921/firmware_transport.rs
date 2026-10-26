//! Retained CONNAC2 firmware transport, adapted from local Linux ecd997b0189a:
//! mt76_connac_mcu.{c,h}, mt7921/{pci,pci_mcu,mcu}.c and mt792x_dma.c.
//! Retains ROM/WM startup, legacy station control, and serialized packet ownership.
use super::fwdl;
use alloc::{collections::VecDeque, sync::Arc, vec, vec::Vec};
use core::{future::poll_fn, ops::Range, task::Poll};

#[path = "station_mcu.rs"]
mod station;
pub use station::{NicCapabilities, PhyCapabilities, RadioInfo};
#[path = "passive_scan.rs"]
mod scan;
pub use scan::{rx_frame, ScanBss, ScanReport};
#[path = "amsdu_rx.rs"]
mod amsdu;
#[path = "station_join.rs"]
mod join;
pub use amsdu::Ht20ReceiveInfo;
pub use join::to_ethernet;
#[path = "recovery.rs"]
mod recovery;
pub(super) use join::{extract_eapol, wrap_eapol_frame};

#[path = "firmware_transport_hw.rs"]
mod hardware;
pub use hardware::Transport;

static BOOT_OWNER: narf_lib::mutex::Mutex<Option<Transport>> = narf_lib::mutex::Mutex::new(None);
// Serializes publication and initial preparation. The work itself lives in
// KEY_WORK, so cancelling a provisioning caller never drops a started owner.
static PROVISION: narf_lib::mutex::Mutex<()> = narf_lib::mutex::Mutex::new(());

type KeyFuture<T> = core::pin::Pin<
    alloc::boxed::Box<dyn core::future::Future<Output = (T, Result<(), Error>)> + Send>,
>;

struct KeyWork<T> {
    future: Option<KeyFuture<T>>,
    completed: Option<(T, Result<(), Error>)>,
}

impl<T> KeyWork<T> {
    fn prepare(
        prepare: impl FnOnce() -> Result<T, Error>,
        start: impl FnOnce(T) -> KeyFuture<T>,
    ) -> Result<Self, Error> {
        let owner = prepare()?;
        Ok(Self {
            future: Some(start(owner)),
            completed: None,
        })
    }

    fn poll(&mut self, cx: &mut core::task::Context<'_>) -> Poll<()> {
        if let Some(future) = self.future.as_mut() {
            if let Poll::Ready(result) = future.as_mut().poll(cx) {
                self.future = None;
                self.completed = Some(result);
            }
        }
        if self.completed.is_some() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

// Rekey/reset work owns the transport across executor polls. Both the normal
// task and a synchronous network drain may advance the retained future.
static KEY_WORK: narf_lib::mutex::Mutex<Option<KeyWork<Transport>>> =
    narf_lib::mutex::Mutex::new(None);

fn poll_boot_keys(cx: &mut core::task::Context<'_>) -> Poll<Result<(), Error>> {
    let Some(mut slot) = KEY_WORK.try_lock() else {
        cx.waker().wake_by_ref();
        return Poll::Pending;
    };
    let Some(work) = slot.as_mut() else {
        return Poll::Ready(Ok(()));
    };
    if work.poll(cx).is_pending() {
        return Poll::Pending;
    }
    let Some(mut owner) = BOOT_OWNER.try_lock() else {
        cx.waker().wake_by_ref();
        return Poll::Pending;
    };
    if owner.is_some() {
        return Poll::Ready(Err(Error::Ring));
    }
    let (transport, result) = work.completed.take().unwrap();
    *owner = Some(transport);
    *slot = None;
    Poll::Ready(result)
}

async fn finish_boot_keys() -> Result<(), Error> {
    poll_fn(poll_boot_keys).await
}

/// Continue initial firmware provisioning on the same parked PCI binding.
/// Missing/invalid assets leave discovery unclaimed and can be replaced before
/// retry. Started work stays retained across caller cancellation; failed work
/// requires the separate verified-reset recovery path, never a fresh claim.
/// Repeating this on an initialized radio preserves its current station state.
pub async fn provision_boot_radio() -> Result<RadioInfo, Error> {
    let Some(_provision) = PROVISION.try_lock() else {
        return Err(Error::Busy);
    };
    finish_boot_keys().await?;
    {
        let Some(mut work) = KEY_WORK.try_lock() else {
            return Err(Error::Busy);
        };
        if work.is_some() {
            return Err(Error::Busy);
        }
        let Some(owner) = BOOT_OWNER.try_lock() else {
            return Err(Error::Busy);
        };
        if owner.is_none() {
            // No await between the exclusive claim and retained installation.
            // Firmware preflight completes before PCI/DMA transport creation.
            *work = Some(KeyWork::prepare(
                || super::pci::claim_firmware_transport()?.ok_or(Error::DeviceGone),
                |mut transport| {
                    alloc::boxed::Box::pin(async move {
                        let result = async {
                            transport.run().await?;
                            transport.initialize_radio().await.map(|_| ())
                        }
                        .await;
                        (transport, result)
                    })
                },
            )?);
        }
    }
    finish_boot_keys().await?;
    let info = {
        let Some(owner) = BOOT_OWNER.try_lock() else {
            return Err(Error::Busy);
        };
        match owner.as_ref().map(Transport::state) {
            Some(State::RadioReady(info) | State::ScanReady(info))
            | Some(State::Associated { info, .. }) => info,
            Some(State::Failed { error, .. }) => return Err(error),
            _ => return Err(Error::Busy),
        }
    };
    crate::iface::register_scan_iface(info).map_err(|_| Error::Authority)?;
    Ok(info)
}

/// Boot-only retained transport diagnostics, independent of radio readiness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootStatus {
    Absent,
    Running,
    Retained(State),
}

/// Inspect without waiting on the boot runner's owner lock.
pub fn boot_status() -> BootStatus {
    match KEY_WORK.try_lock() {
        Some(work) if work.is_none() => {}
        _ => return BootStatus::Running,
    }
    match BOOT_OWNER.try_lock() {
        None => BootStatus::Running,
        Some(owner) => owner.as_ref().map_or(BootStatus::Absent, |owner| {
            BootStatus::Retained(owner.state())
        }),
    }
}

/// Run a receive-only hardware diagnostic using the retained boot owner.
/// May be awaited from the executor; no sync bridge or IRQ lock is held.
pub async fn scan_boot_passive(channels: &[u8]) -> Result<ScanReport, Error> {
    finish_boot_keys().await?;
    let Some(mut owner) = BOOT_OWNER.try_lock() else {
        return Err(Error::Busy);
    };
    owner
        .as_mut()
        .ok_or(Error::DeviceGone)?
        .scan_passive(channels)
        .await
}

/// Policy-authorized active scan through the same retained radio owner.
pub async fn scan_boot_active(channels: &[u8], ssids: &[Vec<u8>]) -> Result<ScanReport, Error> {
    finish_boot_keys().await?;
    let Some(mut owner) = BOOT_OWNER.try_lock() else {
        return Err(Error::Busy);
    };
    owner
        .as_mut()
        .ok_or(Error::DeviceGone)?
        .scan_active(channels, ssids)
        .await
}

/// Dispatch station association using the retained boot owner.
pub async fn associate_boot_station(
    bss: &ScanBss,
    ssid: &[u8],
    security: crate::mt7921::association::Security,
    extra_ies: &[u8],
) -> Result<u16, Error> {
    finish_boot_keys().await?;
    let Some(mut owner) = BOOT_OWNER.try_lock() else {
        return Err(Error::Busy);
    };
    owner
        .as_mut()
        .ok_or(Error::DeviceGone)?
        .associate_station_with_ies(bss, ssid, security, extra_ies)
        .await
}

/// Disassociate the current station using the retained boot owner.
pub async fn disassociate_boot_station() -> Result<(), Error> {
    finish_boot_keys().await?;
    let Some(mut owner) = BOOT_OWNER.try_lock() else {
        return Err(Error::Busy);
    };
    owner
        .as_mut()
        .ok_or(Error::DeviceGone)?
        .disassociate_station()
        .await
}

/// Submit an Ethernet data frame using the retained boot owner.
pub async fn transmit_boot_frame(frame: &[u8]) -> Result<(), Error> {
    finish_boot_keys().await?;
    let Some(mut owner) = BOOT_OWNER.try_lock() else {
        return Err(Error::Busy);
    };
    owner
        .as_mut()
        .ok_or(Error::DeviceGone)?
        .transmit_ethernet(frame)
        .await
}

/// Receive a data frame from the data queue using the retained boot owner.
pub async fn receive_boot_data() -> Result<Option<Vec<u8>>, Error> {
    finish_boot_keys().await?;
    let frame = {
        let Some(mut owner) = BOOT_OWNER.try_lock() else {
            return Err(Error::Busy);
        };
        owner
            .as_mut()
            .ok_or(Error::DeviceGone)?
            .receive_data_frame()
            .await?
    };
    service_boot_keys().await?;
    Ok(frame)
}

/// One bounded packet-service step. No executor task or IRQ wake is needed
/// to retire TX and route RX, so synchronous network waiters can call it.
#[derive(Debug)]
pub struct PacketStep {
    pub transmitted: bool,
    pub received: Vec<Vec<u8>>,
}

pub fn step_boot_network(tx: Option<&[u8]>) -> Result<PacketStep, Error> {
    let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
    match poll_boot_keys(&mut cx) {
        Poll::Ready(result) => result?,
        Poll::Pending => return Err(Error::Busy),
    }
    let Some(mut owner) = BOOT_OWNER.try_lock() else {
        return Err(Error::Busy);
    };
    owner.as_mut().ok_or(Error::DeviceGone)?.step_network(tx)
}

pub async fn service_boot_keys() -> Result<(), Error> {
    {
        let Some(mut work) = KEY_WORK.try_lock() else {
            return Err(Error::Busy);
        };
        if work.is_none() {
            let Some(mut owner) = BOOT_OWNER.try_lock() else {
                return Err(Error::Busy);
            };
            let transport = owner.as_ref().ok_or(Error::DeviceGone)?;
            if !transport.keys_pending() {
                return Ok(());
            }
            let mut transport = owner.take().unwrap();
            *work = Some(KeyWork {
                future: Some(alloc::boxed::Box::pin(async move {
                    let result = transport.service_keys().await;
                    (transport, result)
                })),
                completed: None,
            });
        }
    }
    finish_boot_keys().await
}

/// Recovery owns its transport across polls, including after caller
/// cancellation. Carrier must be closed before this operation is requested.
pub async fn recover_boot_radio(expected_mac: [u8; 6]) -> Result<(), Error> {
    if expected_mac == [0; 6] || expected_mac[0] & 1 != 0 {
        return Err(Error::Bounds);
    }
    reset_boot_transport(Some(expected_mac)).await
}

async fn reset_boot_transport(expected_mac: Option<[u8; 6]>) -> Result<(), Error> {
    // A prior failed rekey must first return its owned transport. Its error
    // explains the closed port; reset below establishes a fresh radio state.
    let _ = finish_boot_keys().await;
    {
        let Some(mut work) = KEY_WORK.try_lock() else {
            return Err(Error::Busy);
        };
        if work.is_some() {
            return Err(Error::Busy);
        }
        let Some(mut owner) = BOOT_OWNER.try_lock() else {
            return Err(Error::Busy);
        };
        if let Some(transport) = owner.as_ref() {
            if let State::RadioReady(info) = transport.state() {
                return if expected_mac.is_none_or(|mac| mac == info.capabilities.mac) {
                    Ok(())
                } else {
                    Err(Error::InvalidIdentity)
                };
            }
        }
        let mut transport = owner.take().ok_or(Error::DeviceGone)?;
        *work = Some(KeyWork {
            future: Some(alloc::boxed::Box::pin(async move {
                let result = match expected_mac {
                    Some(mac) => transport.recover(mac).await,
                    None => transport.recover_unregistered().await,
                }
                .map(|_| ());
                (transport, result)
            })),
            completed: None,
        });
    }
    finish_boot_keys().await
}

pub(super) async fn retry_preflight_until<Step, StepFut, Wait, WaitFut>(
    max_attempts: usize,
    mut status: impl FnMut() -> BootStatus,
    mut step: Step,
    mut wait: Wait,
) -> Result<RadioInfo, Error>
where
    Step: FnMut() -> StepFut,
    StepFut: core::future::Future<Output = Result<RadioInfo, Error>>,
    Wait: FnMut() -> WaitFut,
    WaitFut: core::future::Future<Output = ()>,
{
    let mut last_err = Error::InvalidFirmware;
    for attempt in 0..max_attempts {
        if attempt > 0 {
            wait().await;
        }
        match step().await {
            Ok(info) => return Ok(info),
            Err(err) => {
                last_err = err;
                if !matches!(
                    status(),
                    BootStatus::Absent | BootStatus::Retained(State::RadioReady(_))
                ) {
                    return Err(err);
                }
            }
        }
    }
    Err(last_err)
}

pub(super) fn start_boot() -> narf_init::InitResult {
    use core::fmt::Write;
    use narf_init::InitResult;
    // Before executor polling, regular Mutex (no IRQ spinlock) retained.
    // This future is self-waking and never depends on another executor task.
    let result = narf_scheduler::block_on_spin(provision_boot_radio());
    if result == Err(Error::DeviceGone) && !super::pci::is_probed() {
        return InitResult::NotPresent;
    }
    let _ = writeln!(
        narf_console::Writer,
        "mt76: firmware {result:?}; retained {:?}; station idle; packet service awaits association",
        boot_status()
    );
    if result.is_ok() {
        InitResult::Ok
    } else if matches!(
        boot_status(),
        BootStatus::Absent | BootStatus::Retained(State::RadioReady(_))
    ) {
        // No firmware attempt yet (or net authority arrived after radio bring-up):
        // retry the same parked binding in the background as late firmware scans
        // or userspace staging complete, falling back to verified reset recovery
        // if the subsequent first hardware attempt fails.
        narf_scheduler::spawn(async {
            let outcome = retry_preflight_until(120, boot_status, provision_boot_radio, || {
                narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(500_000_000))
            })
            .await;
            if outcome.is_ok() {
                let _ = writeln!(
                    narf_console::Writer,
                    "mt76: staged firmware provisioned; retained {:?}",
                    boot_status()
                );
                return;
            }
            if !matches!(boot_status(), BootStatus::Absent) {
                for delay_ns in [1_000_000_000, 5_000_000_000, 30_000_000_000] {
                    narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(delay_ns)).await;
                    let result = reset_boot_transport(None).await;
                    let _ = writeln!(
                        narf_console::Writer,
                        "mt76: initial radio recovery {result:?}"
                    );
                    if result.is_ok() {
                        let _ = provision_boot_radio().await;
                        return;
                    }
                }
            }
        });
        InitResult::Error("MT76 firmware preflight (provisioning available)")
    } else {
        // Recovery after initial firmware/radio failure has no registered
        // interface yet. Keep ownership in the same retained worker and only
        // publish an interface after a successful fresh identity query.
        narf_scheduler::spawn(async {
            for delay_ns in [1_000_000_000, 5_000_000_000, 30_000_000_000] {
                narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(delay_ns)).await;
                let result = reset_boot_transport(None).await;
                let _ = writeln!(
                    narf_console::Writer,
                    "mt76: initial radio recovery {result:?}"
                );
                if result.is_ok() {
                    let _ = provision_boot_radio().await;
                    return;
                }
            }
        });
        InitResult::Error("MT76 firmware startup (owner retained)")
    }
}

const COMMAND_HEADER: usize = 64;
const MAX_FRAME: usize = 4096;
const TIMEOUT_MS: u64 = 3000;
const MAX_EVENTS: usize = 32;
const MAX_IMAGE: usize = 16 * 1024 * 1024;

// Shared by the physical backend and cancellation models. A published owner
// cannot infer device quiescence from Rust future/owner lifetime alone.
#[derive(Debug)]
struct Retained<T> {
    storage: Option<T>,
    published: bool,
}
impl<T> Drop for Retained<T> {
    fn drop(&mut self) {
        if self.published {
            if let Some(storage) = self.storage.take() {
                core::mem::forget(storage);
            }
        }
    }
}

/// Firmware/transport failure. A started failure cannot be replayed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    EntropyUnavailable,
    Busy,
    InvalidFirmware,
    UnsupportedFirmware,
    Allocation,
    DmaAddress,
    Authority,
    Bounds,
    DeviceGone,
    Register,
    Timeout,
    Ring,
    MalformedEvent,
    EventOverflow,
    Rejected(u8),
    RejectedCommand(u32),
    InvalidIdentity,
}
/// Last operation reached by a single firmware boot attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    RecoveryPark,
    RecoveryReset,
    RecoveryReady,
    RecoveryRearm,
    Quiesce,
    Initialize,
    DriverOwn,
    Restart,
    RomReady,
    PatchSemaphore,
    PatchDownload,
    PatchFinish,
    PatchRelease,
    RamDownload,
    StartFirmware,
    FirmwareReady,
    NicCapabilities,
    Efuse,
    EepromMode,
    CountryLimits,
    MacInitialize,
    ScanSetup,
    ScanWait,
    ChannelSwitch,
    Authenticate,
    Associate,
    EapolHandshake,
    StaRecord,
    Shutdown,
}
/// Firmware observations, not an operational WLAN interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub version: [u8; 10],
    pub build_date: [u8; 15],
    pub patch_already_loaded: bool,
    pub bytes_transferred: usize,
}
/// Session state survives cancellation of its borrowed run future.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Running(Stage),
    Ready(Report),
    RadioReady(RadioInfo),
    ScanReady(RadioInfo),
    Associated {
        info: RadioInfo,
        peer: [u8; 6],
        channel: u8,
        aid: u16,
    },
    Failed {
        stage: Stage,
        error: Error,
    },
    Stopped,
}
#[derive(Clone, Debug)]
struct Region {
    addr: u32,
    mode: u32,
    bytes: Range<usize>,
}
/// Owned, fully validated firmware; preparation performs no device writes.
#[derive(Clone, Debug)]
pub struct Firmware {
    patch: Arc<[u8]>,
    ram: Arc<[u8]>,
    patch_regions: Vec<Region>,
    ram_regions: Vec<Region>,
    clc_regions: Vec<Range<usize>>,
    version: [u8; 10],
    build_date: [u8; 15],
    override_addr: u32,
}
impl Firmware {
    /// Validate every table, range and mode before any firmware command.
    pub fn prepare(patch: &[u8], ram: &[u8]) -> Result<Self, Error> {
        if patch.len() > MAX_IMAGE || ram.len() > MAX_IMAGE {
            return Err(Error::InvalidFirmware);
        }
        let hdr = fwdl::parse_patch_header(patch).map_err(|_| Error::InvalidFirmware)?;
        let table_end = (hdr.n_region as usize)
            .checked_mul(fwdl::PATCH_SEC_SIZE)
            .and_then(|size| size.checked_add(fwdl::PATCH_HDR_SIZE))
            .ok_or(Error::InvalidFirmware)?;
        if hdr.n_region == 0 || hdr.n_region > 64 || table_end > patch.len() {
            return Err(Error::InvalidFirmware);
        }
        let mut patch_regions = Vec::new();
        for region in fwdl::iter_patch_sections(patch, &hdr).map_err(|_| Error::InvalidFirmware)? {
            let region = region.map_err(|_| Error::InvalidFirmware)?;
            let start = region.offset as usize;
            let end = start
                .checked_add(region.len as usize)
                .ok_or(Error::InvalidFirmware)?;
            if start < table_end
                || end > patch.len()
                || region.len == 0
                || region.len > region.size
                || region.addr.checked_add(region.len).is_none()
            {
                return Err(Error::InvalidFirmware);
            }
            let info = region.sec_key_idx;
            let mode = if info == u32::MAX {
                1 << 31
            } else {
                match info >> 24 {
                    0 => 1 << 31,
                    1 => (1 << 31) | 1 | 8 | ((info & 3) << 1),
                    2 => (1 << 31) | 1 | 8 | 64,
                    _ => return Err(Error::UnsupportedFirmware),
                }
            };
            patch_regions.push(Region {
                addr: region.addr,
                mode,
                bytes: start..end,
            });
        }
        let tail = fwdl::parse_fw_trailer(ram).map_err(|_| Error::InvalidFirmware)?;
        let end = ram
            .len()
            .checked_sub(fwdl::FW_TRAILER_SIZE + usize::from(tail.n_region) * fwdl::FW_REGION_SIZE)
            .ok_or(Error::InvalidFirmware)?;
        if tail.n_region == 0 || tail.n_region > 64 {
            return Err(Error::InvalidFirmware);
        }
        let mut offset = 0usize;
        let mut ram_regions = Vec::new();
        let mut clc_regions = Vec::new();
        let mut override_addr = 0;
        for region in fwdl::iter_fw_regions(ram, &tail).map_err(|_| Error::InvalidFirmware)? {
            let region = region.map_err(|_| Error::InvalidFirmware)?;
            let next = offset
                .checked_add(region.len as usize)
                .ok_or(Error::InvalidFirmware)?;
            if next > end || region.addr.checked_add(region.len).is_none() {
                return Err(Error::InvalidFirmware);
            }
            if region.feature_set & !0x77 != 0
                || region.decomp_len != 0
                || region.decomp_blk_sz != 0
            {
                return Err(Error::UnsupportedFirmware);
            }
            if region.feature_set & 64 == 0 {
                if region.len == 0 {
                    return Err(Error::InvalidFirmware);
                }
                if region.feature_set & 32 != 0 {
                    override_addr = region.addr;
                }
                let mode = (1 << 31)
                    | u32::from(region.feature_set & 6)
                    | if region.feature_set & 1 != 0 { 9 } else { 0 }
                    | if region.feature_set & 16 != 0 { 64 } else { 0 };
                ram_regions.push(Region {
                    addr: region.addr,
                    mode,
                    bytes: offset..next,
                });
            } else if region.region_type == 2 {
                station::validate_clc_tables(&ram[offset..next])?;
                clc_regions.push(offset..next);
            }
            offset = next;
        }
        if ram_regions.is_empty() {
            return Err(Error::InvalidFirmware);
        }
        Ok(Self {
            patch: patch.into(),
            ram: ram.into(),
            patch_regions,
            ram_regions,
            clc_regions,
            version: tail.fw_ver,
            build_date: tail.build_date,
            override_addr,
        })
    }
    /// Copy verified registry payloads into this session's immutable ownership.
    pub fn open(
        did: u16,
        auth: &narf_capabilities::Cap<narf_firmware::FirmwareRegistry, narf_capabilities::Read>,
    ) -> Result<Self, Error> {
        let (patch, ram) = super::pci::firmware_blobs_for(did);
        let patch = super::firmware_assets::load(auth, patch)?;
        let ram = super::firmware_assets::load(auth, ram)?;
        Self::prepare(&patch, &ram)
    }
}

fn command_frame(command: u8, seq: u8, payload: &[u8]) -> Result<Vec<u8>, Error> {
    if seq == 0 || seq > 15 || payload.len() > MAX_FRAME - COMMAND_HEADER {
        return Err(Error::Bounds);
    }
    let mut frame = vec![0; COMMAND_HEADER + payload.len()];
    let len = frame.len();
    frame[..4].copy_from_slice(&((len as u32) | (2 << 23) | (0x20 << 25)).to_le_bytes());
    frame[4..8].copy_from_slice(&((1u32 << 31) | (1 << 16)).to_le_bytes());
    frame[32..34].copy_from_slice(&((len - 32) as u16).to_le_bytes());
    frame[34..36].copy_from_slice(&0x8000u16.to_le_bytes());
    frame[36] = command;
    frame[37] = 0xa0;
    frame[38] = 3;
    frame[39] = seq;
    frame[COMMAND_HEADER..].copy_from_slice(payload);
    Ok(frame)
}

trait Backend {
    /// Protocol nonce entropy is fallible; deterministic fixtures override this
    /// boundary, while the native backend always requires the architectural RNG.
    fn random_bytes(&mut self, out: &mut [u8]) -> Result<(), Error> {
        narf_crypto::try_fill_random_bytes(out).map_err(|_| Error::EntropyUnavailable)
    }
    fn progress(&mut self, _stage: Stage) {}
    fn now_ns(&self) -> u64;
    fn check(&self) -> Result<(), Error>;
    fn check_tx_permission(
        &self,
        permission: crate::mt7921::association::TxPermission,
    ) -> Result<(), Error>;
    fn quiesce(&mut self) -> Result<(), Error>;
    fn idle(&mut self) -> Result<bool, Error>;
    fn initialize(&mut self) -> Result<(), Error>;
    fn request_driver_own(&mut self) -> Result<(), Error>;
    fn driver_owned(&mut self) -> Result<bool, Error>;
    fn fw_state(&mut self) -> Result<u32, Error>;
    fn submit(&mut self, scatter: bool, frame: &[u8]) -> Result<(), Error>;
    fn tx_complete(&mut self, scatter: bool) -> Result<bool, Error>;
    fn receive(&mut self) -> Result<Option<Vec<u8>>, Error>;
    fn receive_data(&mut self) -> Result<Option<Vec<u8>>, Error>;
    fn release(&mut self) -> Result<(), Error>;
    fn park_bus_master(&mut self) -> Result<(), Error>;
    fn request_link_own(&mut self) -> Result<(), Error>;
    fn link_owned(&mut self) -> Result<bool, Error>;
    fn assert_reset(&mut self) -> Result<(), Error>;
    fn release_reset(&mut self) -> Result<(), Error>;
    fn reset_done(&mut self) -> Result<bool, Error>;
    /// Only called after release() has proved DMA idle, bus mastering off
    /// and every device ring reference cleared.
    fn recycle(&mut self) -> Result<(), Error>;
    fn configure_mac(&mut self) -> Result<(), Error>;
    fn clear_wtbl(&mut self, index: u8) -> Result<(), Error>;
    fn wtbl_idle(&mut self) -> Result<bool, Error>;
    fn submit_management(
        &mut self,
        frame: &[u8],
        wcid: u16,
        rate: crate::mt7921::association::LegacyRate,
    ) -> Result<(), Error>;
    fn management_complete(
        &mut self,
    ) -> Result<Option<crate::mt7921::packet_tx::Completion>, Error>;
    fn submit_data(&mut self, frame: &[u8], protected: bool, qos: bool) -> Result<(), Error>;
}

/// Active station checks consume only the currently installed snapshot.
/// Policy bootstrapping belongs to explicit pre-admission entry points; a
/// cleared database cannot silently recreate an earlier station's grant.
fn current_station_permission(
    permission: crate::mt7921::association::TxPermission,
    current: Option<Arc<narf_wireless::reg::RegulatoryDomain>>,
) -> Result<(), Error> {
    if current.is_some_and(|domain| permission.current(&domain)) {
        Ok(())
    } else {
        Err(Error::Authority)
    }
}

#[derive(Debug)]
struct Session<B: Backend> {
    backend: B,
    firmware: Firmware,
    state: State,
    seq: u8,
    events: VecDeque<Vec<u8>>,
    transferred: usize,
    boot_started: Option<u64>,
    scan_seq: u8,
    security: Option<join::StationSecurity>,
    management_rate: crate::mt7921::association::LegacyRate,
    data_pending: Option<u64>,
    peer_lost: bool,
    station_bss: Option<ScanBss>,
    station_permission: Option<crate::mt7921::association::TxPermission>,
    wmm: Option<crate::mt7921::association::wmm::Parameters>,
    ht20_rx: Option<amsdu::Receiver>,
    ht20_profile: Option<crate::mt7921::ht20::Profile>,
    control_pending: VecDeque<Vec<u8>>,
    received_msdu: VecDeque<Vec<u8>>,
}
impl<B: Backend> Session<B> {
    fn new(backend: B, firmware: Firmware) -> Self {
        Self {
            backend,
            firmware,
            state: State::Prepared,
            seq: 0,
            events: VecDeque::new(),
            transferred: 0,
            boot_started: None,
            scan_seq: 0,
            security: None,
            management_rate: crate::mt7921::association::LegacyRate::ONE_MBPS,
            data_pending: None,
            peer_lost: false,
            station_bss: None,
            station_permission: None,
            wmm: None,
            ht20_rx: None,
            ht20_profile: None,
            control_pending: VecDeque::new(),
            received_msdu: VecDeque::new(),
        }
    }
    fn stage(&mut self, stage: Stage) {
        self.state = State::Running(stage);
        self.backend.progress(stage);
    }
    async fn wait<T>(
        &mut self,
        ms: u64,
        mut f: impl FnMut(&mut B) -> Result<Option<T>, Error>,
    ) -> Result<T, Error> {
        let start = self.backend.now_ns();
        poll_fn(|cx| {
            if let Err(error) = self.backend.check() {
                return Poll::Ready(Err(error));
            }
            let now = self.backend.now_ns();
            if self
                .boot_started
                .is_some_and(|began| now.saturating_sub(began) >= 30_000_000_000)
                || now.saturating_sub(start) >= ms * 1_000_000
            {
                return Poll::Ready(Err(Error::Timeout));
            }
            match f(&mut self.backend) {
                Ok(Some(value)) => Poll::Ready(Ok(value)),
                Err(error) => Poll::Ready(Err(error)),
                Ok(None) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        })
        .await
    }
    async fn send(&mut self, scatter: bool, frame: &[u8]) -> Result<(), Error> {
        self.backend.check()?;
        if self
            .boot_started
            .is_some_and(|began| self.backend.now_ns().saturating_sub(began) >= 30_000_000_000)
        {
            return Err(Error::Timeout);
        }
        self.backend.submit(scatter, frame)?;
        self.wait(TIMEOUT_MS, |backend| {
            backend.tx_complete(scatter).map(|done| done.then_some(()))
        })
        .await
    }
    async fn command(&mut self, cmd: u8, body: &[u8], response: bool) -> Result<u8, Error> {
        self.seq = self.seq % 15 + 1;
        let seq = self.seq;
        let frame = command_frame(cmd, seq, body)?;
        self.send(false, &frame).await?;
        if !response {
            return Ok(0);
        }
        let start = self.backend.now_ns();
        loop {
            let remaining = (TIMEOUT_MS * 1_000_000)
                .saturating_sub(self.backend.now_ns().saturating_sub(start));
            if remaining < 1_000_000 {
                return Err(Error::Timeout);
            }
            let event = self.wait(remaining / 1_000_000, Backend::receive).await?;
            if event.len() < 32 {
                return Err(Error::MalformedEvent);
            }
            let size = usize::from(u16::from_le_bytes([event[24], event[25]]));
            if size < 8 || size + 24 > event.len() {
                return Err(Error::MalformedEvent);
            }
            if event[29] != seq || event[30] & 4 != 0 {
                if self.events.len() == MAX_EVENTS {
                    return Err(Error::EventOverflow);
                }
                self.events.push_back(event);
                continue;
            }
            if cmd == 0x10 || cmd == 0x07 {
                if !matches!(event[28], 1 | 4) || size + 24 < 33 {
                    return Err(Error::MalformedEvent);
                }
                return Ok(event[32]);
            }
            if size < 12 || event[28] != 1 {
                return Err(Error::MalformedEvent);
            }
            return Ok(0);
        }
    }
    async fn download(&mut self, source: &[u8], region: &Region) -> Result<(), Error> {
        let mut body = [0; 12];
        fwdl::encode_target_address_len_req(
            region.addr,
            region.bytes.len() as u32,
            region.mode,
            &mut body,
        )
        .ok_or(Error::Bounds)?;
        let cmd = if matches!(region.addr, 0x200000 | 0x900000) {
            5
        } else {
            1
        };
        self.command(cmd, &body, true).await?;
        for chunk in source[region.bytes.clone()].chunks(MAX_FRAME) {
            self.seq = self.seq % 15 + 1; // Linux advances even for headerless FW_SCATTER.
            self.send(true, chunk).await?;
            self.transferred += chunk.len();
        }
        Ok(())
    }
    async fn run(&mut self) -> Result<Report, Error> {
        if self.state != State::Prepared {
            return Err(Error::Busy);
        }
        self.boot_started = Some(self.backend.now_ns());
        let result = self.boot().await;
        match result {
            Ok(report) => {
                self.state = State::Ready(report);
                Ok(report)
            }
            Err(error) => {
                let stage = match self.state {
                    State::Running(stage) => stage,
                    _ => Stage::Initialize,
                };
                self.state = State::Failed { stage, error };
                Err(error)
            }
        }
    }
    async fn boot(&mut self) -> Result<Report, Error> {
        self.stage(Stage::Quiesce);
        self.backend.check()?;
        self.backend.quiesce()?;
        self.wait(100, |b| b.idle().map(|idle| idle.then_some(())))
            .await?;
        self.stage(Stage::Initialize);
        self.backend.initialize()?;
        self.stage(Stage::DriverOwn);
        self.backend.request_driver_own()?;
        self.wait(500, |b| b.driver_owned().map(|ready| ready.then_some(())))
            .await?;
        self.stage(Stage::Restart);
        self.command(4, &[1, 0, 0, 0], false).await?;
        self.stage(Stage::RomReady);
        self.wait(1000, |b| {
            b.fw_state().map(|state| (state & 7 == 1).then_some(()))
        })
        .await?;
        self.stage(Stage::PatchSemaphore);
        let sem = self.command(0x10, &1u32.to_le_bytes(), true).await?;
        let patch_already_loaded = sem == 1;
        if sem != 1 && sem != 2 {
            return Err(Error::Rejected(sem));
        }
        // Clone immutable ownership so no blob borrow spans a mutable session borrow.
        let firmware = self.firmware.clone();
        if !patch_already_loaded {
            self.stage(Stage::PatchDownload);
            for region in &firmware.patch_regions {
                self.download(&firmware.patch, region).await?;
            }
            self.stage(Stage::PatchFinish);
            let status = self.command(7, &[0; 4], true).await?;
            if status != 0 {
                return Err(Error::Rejected(status));
            }
            self.stage(Stage::PatchRelease);
            let status = self.command(0x10, &0u32.to_le_bytes(), true).await?;
            if status != 3 {
                return Err(Error::Rejected(status));
            }
        }
        self.stage(Stage::RamDownload);
        for region in &firmware.ram_regions {
            self.download(&firmware.ram, region).await?;
        }
        self.stage(Stage::StartFirmware);
        let mut body = [0; 8];
        fwdl::encode_fw_start_req(
            u32::from(firmware.override_addr != 0),
            firmware.override_addr,
            &mut body,
        )
        .ok_or(Error::Bounds)?;
        self.command(2, &body, true).await?;
        self.stage(Stage::FirmwareReady);
        self.wait(1500, |b| {
            b.fw_state().map(|state| (state & 3 == 3).then_some(()))
        })
        .await?;
        Ok(Report {
            version: firmware.version,
            build_date: firmware.build_date,
            patch_already_loaded,
            bytes_transferred: self.transferred,
        })
    }
    async fn shutdown(&mut self) -> Result<(), Error> {
        if self.state == State::Stopped {
            return Ok(());
        }
        self.boot_started = None;
        self.stage(Stage::Shutdown);
        let result = async {
            self.backend.check()?;
            self.backend.quiesce()?;
            self.wait(100, |b| b.idle().map(|idle| idle.then_some(())))
                .await?;
            self.backend.release()
        }
        .await;
        match result {
            Ok(()) => {
                self.state = State::Stopped;
                Ok(())
            }
            Err(error) => {
                self.state = State::Failed {
                    stage: Stage::Shutdown,
                    error,
                };
                Err(error)
            }
        }
    }
}

#[path = "firmware_transport_tests.rs"]
mod tests;
