//! Retained CONNAC2 firmware transport, adapted from local Linux ecd997b0189a:
//! mt76_connac_mcu.{c,h}, mt7921/{pci,pci_mcu,mcu}.c and mt792x_dma.c.
//! Retains ROM/WM startup, station control, and bounded native packet ownership.
use super::fwdl;
use alloc::{collections::VecDeque, sync::Arc, vec, vec::Vec};
use core::{future::poll_fn, ops::Range, task::Poll};

#[path = "ap_session.rs"]
mod ap;
#[path = "p2p_device.rs"]
mod p2p;
pub(crate) use ap::ApRxEvent;
pub(crate) type ApEvent = ap::ApEvent;
#[path = "ap_crypto.rs"]
mod ap_crypto;
#[path = "ap_packet.rs"]
mod ap_packet;
#[path = "ap_peer.rs"]
mod ap_peer;
#[path = "ap_rx.rs"]
mod ap_rx;
#[path = "boot_ap.rs"]
pub(crate) mod boot_ap;
#[path = "boot_p2p.rs"]
pub(crate) mod boot_p2p;
#[path = "p2p_management.rs"]
mod p2p_management;
#[path = "p2p_management_capture.rs"]
mod p2p_management_capture;
#[path = "p2p_management_filters.rs"]
pub(crate) mod p2p_management_filters;
#[path = "p2p_management_implicit.rs"]
mod p2p_management_implicit;
#[path = "p2p_management_power.rs"]
mod p2p_management_power;
#[path = "p2p_management_tx.rs"]
mod p2p_management_tx;
#[path = "p2p_management_tx_wire.rs"]
mod p2p_management_tx_wire;
#[path = "p2p_management_wire.rs"]
mod p2p_management_wire;
#[path = "p2p_profile.rs"]
mod p2p_profile;
pub(crate) use p2p_profile::P2pProfile;

#[path = "go_link.rs"]
mod go_link;
#[path = "group_link.rs"]
mod group_link;
#[path = "station_mcu.rs"]
mod station;
pub use station::{NicCapabilities, PhyCapabilities, RadioInfo};
#[path = "passive_scan.rs"]
mod scan;
pub use scan::{
    rx_frame, validate_scan_options, validate_scan_probe_ies, ScanBss, ScanOptions, ScanReport,
    MAX_SCAN_IE_LEN,
};
#[path = "amsdu_rx.rs"]
mod amsdu;
#[path = "rx_ba.rs"]
mod ba;
#[path = "rx_ba_station.rs"]
mod ba_station;
#[path = "rx_fragment.rs"]
mod fragment;
#[path = "station_join.rs"]
mod join;
#[path = "tx_ba.rs"]
mod tx_ba;
#[path = "tx_ba_restart.rs"]
mod tx_ba_restart;
#[path = "tx_ba_station.rs"]
mod tx_ba_station;
pub use amsdu::Ht20ReceiveInfo;
pub use join::to_ethernet;
#[path = "monitor.rs"]
mod monitor;
#[path = "recovery.rs"]
mod recovery;
#[path = "system_pm.rs"]
mod system_pm;
#[path = "wowlan_station.rs"]
mod wowlan;
#[path = "wowlan_owner.rs"]
mod wowlan_owner;
pub(super) use join::{extract_eapol, wrap_eapol_frame};
pub use monitor::{validate_channel as validate_monitor_channel, Capture as MonitorCapture};
pub use wowlan_owner::{boot_validate_rekey_data, boot_wake_route_available, suspend_boot_wowlan};

#[path = "firmware_transport_hw.rs"]
mod hardware;
pub use hardware::Transport;

static BOOT_OWNER: narf_lib::mutex::Mutex<Option<Transport>> = narf_lib::mutex::Mutex::new(None);
/// Set once the boot-time firmware initcall ran; later probes provision
/// themselves.
static BOOT_STARTED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
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
    *slot = None;
    let generation = transport.generation();
    let current = super::pci::generation();
    if generation != current {
        drop(owner);
        let _ = admit_completed(transport, generation, current, retire_transport);
        return Poll::Ready(Err(Error::DeviceGone));
    }
    *owner = Some(transport);
    Poll::Ready(result)
}

/// Completed retained work is republished only into its own PCI binding
/// generation. A function removed while the work owned its transport gets
/// the removal teardown instead, never a new publication.
fn admit_completed<T>(
    owner: T,
    generation: u64,
    current: u64,
    retire: impl FnOnce(T),
) -> Result<T, Error> {
    if generation == current {
        Ok(owner)
    } else {
        retire(owner);
        Err(Error::DeviceGone)
    }
}

fn retire_transport(mut transport: Transport) {
    let generation = transport.generation();
    // Unproven retirement keeps the published rings forever (Retained), so
    // a later generation's freshly programmed rings can never alias them;
    // behind a per-domain IOMMU they are freed only after a completed DMA
    // block of the function (`Hardware` drop).
    let _ = transport.retire_removed();
    drop(transport);
    super::pci::release_transport_claim(generation);
}

/// Removal of binding `generation` (Linux `mt7921e_unregister_device`).
/// Returns whether the transport is gone with its DMA retirement proven.
/// Work in flight or a caller holding the owner keeps the transport; it is
/// retired by a reaper as soon as it is returned, never republished.
pub(super) fn retire_for_removal(generation: u64) -> bool {
    let busy = KEY_WORK.try_lock().is_none_or(|work| work.is_some());
    if !busy {
        if let Some(mut owner) = BOOT_OWNER.try_lock() {
            match owner.take() {
                None => return true,
                Some(mut transport) if transport.generation() == generation => {
                    drop(owner);
                    let proven = transport.retire_removed();
                    drop(transport);
                    return proven;
                }
                Some(transport) => {
                    *owner = Some(transport);
                    return true;
                }
            }
        }
    }
    narf_scheduler::spawn(async move {
        // Drive retained work to completion: its stale generation makes
        // poll_boot_keys retire instead of republish.
        loop {
            let _ = finish_boot_keys().await;
            let idle = KEY_WORK.try_lock().is_some_and(|work| work.is_none());
            if idle {
                let mut owner = BOOT_OWNER.lock().await;
                if owner
                    .as_ref()
                    .is_some_and(|transport| transport.generation() == generation)
                {
                    let transport = owner.take().unwrap();
                    drop(owner);
                    retire_transport(transport);
                }
                return;
            }
            narf_scheduler::yield_now().await;
        }
    });
    false
}

/// A probe after boot-time provisioning (hot-plug/reprobe) starts its own
/// retried firmware provisioning on the new generation.
pub(super) fn provision_after_reprobe() {
    if !BOOT_STARTED.load(core::sync::atomic::Ordering::Acquire) {
        return;
    }
    narf_scheduler::spawn(async {
        use core::fmt::Write;
        let outcome = retry_preflight_until(120, boot_status, provision_boot_radio, || {
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(500_000_000))
        })
        .await;
        let _ = writeln!(
            narf_console::Writer,
            "mt76: reprobe provisioning {:?}; retained {:?}",
            outcome.map(|_| ()),
            boot_status()
        );
    });
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
    if crate::module_host::owns_discovery() {
        return Err(Error::Busy);
    }
    provision_radio_inner().await
}

pub(crate) async fn provision_module_radio_once() -> Result<RadioInfo, Error> {
    provision_radio_inner().await
}

async fn provision_radio_inner() -> Result<RadioInfo, Error> {
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
    let (info, profile) = {
        let Some(owner) = BOOT_OWNER.try_lock() else {
            return Err(Error::Busy);
        };
        let info = match owner.as_ref().map(Transport::state) {
            Some(State::RadioReady(info) | State::ScanReady(info) | State::P2pDevice(info))
            | Some(State::Associated { info, .. } | State::AccessPoint { info, .. }) => info,
            Some(State::Failed { error, .. }) => return Err(error),
            _ => return Err(Error::Busy),
        };
        (
            info,
            owner.as_ref().and_then(|owner| owner.p2p_profile().ok()),
        )
    };
    crate::iface::register_scan_iface_profile(info, profile).map_err(|_| Error::Authority)?;
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

/// Copy only the executable images already opened and validated for the
/// current native transport. There is no arbitrary registry name or new
/// registry authority at the module boundary.
pub(crate) fn module_firmware_chunk(
    image: u8,
    offset: usize,
    len: usize,
) -> Result<Vec<u8>, Error> {
    let owner = BOOT_OWNER.try_lock().ok_or(Error::Busy)?;
    owner
        .as_ref()
        .ok_or(Error::DeviceGone)?
        .module_firmware_chunk(image, offset, len)
}

/// Run a receive-only hardware diagnostic using the retained boot owner.
/// May be awaited from the executor; no sync bridge or IRQ lock is held.
pub async fn scan_boot_passive(channels: &[u8]) -> Result<ScanReport, Error> {
    scan_boot_with_options(channels, &[], ScanOptions::default()).await
}

/// Policy-authorized active scan through the same retained radio owner.
pub async fn scan_boot_active(channels: &[u8], ssids: &[Vec<u8>]) -> Result<ScanReport, Error> {
    scan_boot_active_with_ies(channels, ssids, &[]).await
}
/// Active probes with a validated, owned600-byte native IE field.
pub async fn scan_boot_active_with_ies(
    channels: &[u8],
    ssids: &[Vec<u8>],
    extra_ies: &[u8],
) -> Result<ScanReport, Error> {
    if ssids.is_empty() {
        return Err(Error::Bounds);
    }
    scan_boot_with_options(
        channels,
        ssids,
        ScanOptions {
            extra_ies,
            random_mac: None,
        },
    )
    .await
}
/// Retained active/passive scan with source-defined per-request options.
pub async fn scan_boot_with_options(
    channels: &[u8],
    ssids: &[Vec<u8>],
    options: ScanOptions<'_>,
) -> Result<ScanReport, Error> {
    validate_scan_options(options)?;
    finish_boot_keys().await?;
    let Some(mut owner) = BOOT_OWNER.try_lock() else {
        return Err(Error::Busy);
    };
    owner
        .as_mut()
        .ok_or(Error::DeviceGone)?
        .scan_with_options(channels, ssids, options)
        .await
}

/// Start passive capture through the retained native owner. Cancellation
/// retains Running and requires recovery before another role can start.
pub async fn start_boot_monitor(channel: narf_wireless::monitor::Channel) -> Result<(), Error> {
    finish_boot_keys().await?;
    let Some(mut owner) = BOOT_OWNER.try_lock() else {
        return Err(Error::Busy);
    };
    owner
        .as_mut()
        .ok_or(Error::DeviceGone)?
        .start_monitor(channel)
        .await
}
pub async fn stop_boot_monitor() -> Result<(), Error> {
    finish_boot_keys().await?;
    let Some(mut owner) = BOOT_OWNER.try_lock() else {
        return Err(Error::Busy);
    };
    owner
        .as_mut()
        .ok_or(Error::DeviceGone)?
        .stop_monitor()
        .await
}
pub fn step_boot_monitor() -> Result<MonitorCapture, Error> {
    let domain = narf_wireless::reg::db::get_domain().ok_or(Error::Authority)?;
    let Some(mut owner) = BOOT_OWNER.try_lock() else {
        return Err(Error::Busy);
    };
    owner
        .as_mut()
        .ok_or(Error::DeviceGone)?
        .step_monitor(&domain)
}

/// Explicit originator control on the same retained registered radio. The
/// requested TID must still have its fresh native sequence; the packet owner
/// rejects queued DATA, pending key/control work and any used TID.
pub async fn negotiate_boot_transmit_ba_tid(tid: u8) -> Result<bool, Error> {
    if tid >= 8 {
        return Err(Error::Bounds);
    }
    finish_boot_keys().await?;
    let Some(mut owner) = BOOT_OWNER.try_lock() else {
        return Err(Error::Busy);
    };
    owner
        .as_mut()
        .ok_or(Error::DeviceGone)?
        .negotiate_transmit_ba_tid(tid)
        .await
}

/// Queue midstream BA restart on the actual retained radio. No fabricated
/// packet is sent: the next real user MPDU supplies a native TXS sample.
pub async fn request_boot_transmit_ba_restart_tid(tid: u8) -> Result<(), Error> {
    if tid >= 8 {
        return Err(Error::Bounds);
    }
    finish_boot_keys().await?;
    let Some(mut owner) = BOOT_OWNER.try_lock() else {
        return Err(Error::Busy);
    };
    owner
        .as_mut()
        .ok_or(Error::DeviceGone)?
        .request_transmit_ba_restart_tid(tid)
        .await
}

/// Dispatch station association using the retained boot owner.
pub async fn associate_boot_station(
    bss: &ScanBss,
    ssid: &[u8],
    security: crate::mt7921::association::Security,
    extra_ies: &[u8],
) -> Result<u16, Error> {
    associate_boot_station_as(bss, ssid, security, extra_ies, false, false).await
}

/// Station or P2P-client (`p2p_client`) join on the retained boot owner.
/// `heard_beacon`: the latest scan received the BSS's own Beacon, which lets
/// an infrastructure station follow it onto a radar/NO_IR channel.
pub(crate) async fn associate_boot_station_as(
    bss: &ScanBss,
    ssid: &[u8],
    security: crate::mt7921::association::Security,
    extra_ies: &[u8],
    p2p_client: bool,
    heard_beacon: bool,
) -> Result<u16, Error> {
    finish_boot_keys().await?;
    let Some(mut owner) = BOOT_OWNER.try_lock() else {
        return Err(Error::Busy);
    };
    let network = if p2p_client {
        crate::mt7921::p2p_wire::Network::P2p
    } else {
        crate::mt7921::p2p_wire::Network::Infrastructure
    };
    owner
        .as_mut()
        .ok_or(Error::DeviceGone)?
        .associate_station_as(
            bss,
            ssid,
            security,
            extra_ies,
            network,
            heard_beacon && !p2p_client,
        )
        .await
}

/// Roam the home station to `bss` within the ESS (cfg80211 CONNECT with
/// NL80211_ATTR_PREV_BSSID, mac80211 reassociation): leave the current AP
/// `current_ap` with a deauthentication and its keys retired, then join
/// `bss` with a Reassociation Request naming `current_ap`.
pub(crate) async fn reassociate_boot_station(
    bss: &ScanBss,
    ssid: &[u8],
    security: crate::mt7921::association::Security,
    extra_ies: &[u8],
    heard_beacon: bool,
    current_ap: [u8; 6],
) -> Result<u16, Error> {
    disassociate_boot_station().await?;
    {
        let Some(mut owner) = BOOT_OWNER.try_lock() else {
            return Err(Error::Busy);
        };
        owner
            .as_mut()
            .ok_or(Error::DeviceGone)?
            .set_reassociation(current_ap);
    }
    associate_boot_station_as(bss, ssid, security, extra_ies, false, heard_beacon).await
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
    let (frame, epoch) = {
        let Some(mut owner) = BOOT_OWNER.try_lock() else {
            return Err(Error::Busy);
        };
        let owner = owner.as_mut().ok_or(Error::DeviceGone)?;
        let epoch = owner.current_receive_epoch()?;
        (owner.receive_data_frame().await?, epoch)
    };
    finish_received_data(frame, epoch, service_boot_keys(), boot_receive_current).await
}

/// The direct async API has the same final-owner check as packet batches.
/// Key service can replace its receive epoch after extraction releases BOOT_OWNER.
async fn finish_received_data(
    frame: Option<Vec<u8>>,
    epoch: Option<u64>,
    service: impl core::future::Future<Output = Result<(), Error>>,
    current: impl FnOnce(u64) -> Result<bool, Error>,
) -> Result<Option<Vec<u8>>, Error> {
    service.await?;
    match (frame, epoch) {
        (Some(frame), Some(epoch)) if current(epoch)? => Ok(Some(frame)),
        _ => Ok(None),
    }
}

/// One bounded packet-service step. No executor task or IRQ wake is needed
/// to retire TX and route RX, so synchronous network waiters can call it.
#[derive(Debug)]
pub struct PacketStep {
    pub transmitted: bool,
    pub received: Vec<Vec<u8>>,
    /// The station link's statistics after this step (station steps only).
    pub(crate) link: Option<crate::mt7921::link_stats::LinkStats>,
    /// Identifies the actual station/key receive owner that produced the batch.
    pub receive_epoch: u64,
}

/// Recheck before every unlocked kernel callback and IPC publication. A
/// retained key future temporarily removes BOOT_OWNER, closing publication.
/// False drops only this stale batch and must not tear down a newer owner.
pub fn boot_receive_current(epoch: u64) -> Result<bool, Error> {
    let Some(owner) = BOOT_OWNER.try_lock() else {
        return Ok(false);
    };
    owner
        .as_ref()
        .map_or(Ok(false), |owner| owner.receive_current(epoch))
}
pub(crate) fn boot_refresh_receive_epoch(refresh: impl FnOnce(Option<u64>)) -> Result<(), Error> {
    let Some(owner) = BOOT_OWNER.try_lock() else {
        return Err(Error::Busy);
    };
    let epoch = owner
        .as_ref()
        .map_or(Ok(None), |owner| owner.current_receive_epoch())?;
    refresh(epoch);
    Ok(())
}
/// Non-reentrant IPC/module-byte publication only: no reentrant driver/module
/// callback or await may occur while this final epoch check holds key ownership.
pub(crate) fn boot_receive_publish(epoch: u64, publish: impl FnOnce()) -> Result<bool, Error> {
    let Some(owner) = BOOT_OWNER.try_lock() else {
        return Ok(false);
    };
    let Some(owner) = owner.as_ref() else {
        return Ok(false);
    };
    owner.publish_receive(epoch, publish)
}

/// cfg80211 `wiphy->frag_threshold` as set through
/// `WirelessNetIface::set_fragmentation_threshold` (`u32::MAX` = off). The
/// boot owner samples it before each packet step.
pub(crate) static BOOT_FRAG_THRESHOLD: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(u32::MAX);

/// NL80211_CMD_DEL_PMKSA / FLUSH_PMKSA for the home station's SAE PMKSA
/// cache, applied by the boot owner before each join and packet step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PmksaRequest {
    Flush,
    Bssid([u8; 6]),
    Pmkid([u8; 16]),
}
pub(crate) static BOOT_PMKSA_REQUESTS: narf_lib::sync::IrqSafeSpinLock<Vec<PmksaRequest>> =
    narf_lib::sync::IrqSafeSpinLock::new(Vec::new());

/// Apply queued PMKSA requests to `cache`.
pub(crate) fn apply_pmksa_requests(cache: &mut crate::mt7921::pmksa::Cache) {
    let requests = core::mem::take(&mut *BOOT_PMKSA_REQUESTS.lock());
    for request in requests {
        match request {
            PmksaRequest::Flush => cache.flush(),
            PmksaRequest::Bssid(bssid) => cache.remove(bssid),
            PmksaRequest::Pmkid(pmkid) => cache.remove_pmkid(pmkid),
        }
    }
}

/// cfg80211 `wdev->ps` for the home station (`NL80211_CMD_SET_POWER_SAVE`):
/// on by default as with `CONFIG_CFG80211_DEFAULT_PS`. The boot owner
/// samples it before each packet step and applies it to an associated BSS.
pub(crate) static BOOT_POWER_SAVE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(true);

pub fn step_boot_network(tx: Option<&[u8]>) -> Result<PacketStep, Error> {
    prepare_boot_keys()?;
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

fn prepare_boot_keys() -> Result<(), Error> {
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
    Ok(())
}
pub async fn service_boot_keys() -> Result<(), Error> {
    prepare_boot_keys()?;
    finish_boot_keys().await
}

/// Borrow the retained boot owner after pending key work (the same
/// ownership rule as every other boot-owner entry).
macro_rules! boot_owner_call {
    ($owner:ident => $call:expr) => {{
        finish_boot_keys().await?;
        let Some(mut guard) = BOOT_OWNER.try_lock() else {
            return Err(Error::Busy);
        };
        let $owner = guard.as_mut().ok_or(Error::DeviceGone)?;
        $call.await
    }};
}

/// Publish the concurrent P2P-client group vif `vif` with own address
/// `own` on the retained boot owner (Linux `mt7921_add_interface`).
pub(crate) async fn start_boot_group_link(
    vif: crate::mt7921::vif_slots::Vif,
    own: [u8; 6],
) -> Result<crate::mt7921::vif_slots::Link, Error> {
    boot_owner_call!(owner => owner.start_group_link(vif, own))
}
/// Retire the idle group vif (`mt792x_remove_interface`).
pub(crate) async fn stop_boot_group_link(
    link: crate::mt7921::vif_slots::Link,
) -> Result<(), Error> {
    boot_owner_call!(owner => owner.stop_group_link(link))
}
/// Join the group link as a P2P client (`p2p_client`) or second station.
pub(crate) async fn associate_boot_group(
    link: crate::mt7921::vif_slots::Link,
    bss: &ScanBss,
    ssid: &[u8],
    security: crate::mt7921::association::Security,
    extra_ies: &[u8],
    p2p_client: bool,
) -> Result<u16, Error> {
    let network = if p2p_client {
        crate::mt7921::p2p_wire::Network::P2p
    } else {
        crate::mt7921::p2p_wire::Network::Infrastructure
    };
    boot_owner_call!(owner => owner.associate_group(link, bss, ssid, security, extra_ies, network))
}
/// Leave the group link's association (deauth, key/WCID/BSS retirement).
pub(crate) async fn disassociate_boot_group(
    link: crate::mt7921::vif_slots::Link,
) -> Result<(), Error> {
    boot_owner_call!(owner => owner.disassociate_group(link))
}
/// Explicit group-link originator BA for an unused TID.
pub(crate) async fn negotiate_boot_group_transmit_ba_tid(
    link: crate::mt7921::vif_slots::Link,
    tid: u8,
) -> Result<bool, Error> {
    if tid >= 8 {
        return Err(Error::Bounds);
    }
    boot_owner_call!(owner => owner.negotiate_group_transmit_ba_tid(link, tid))
}
/// One bounded group-link packet step. Pending home or group key work
/// first runs through the shared retained key owner (`prepare_boot_keys`
/// covers both owners), exactly as `step_boot_network`.
pub(crate) fn step_boot_group_network(
    link: crate::mt7921::vif_slots::Link,
    tx: Option<&[u8]>,
) -> Result<PacketStep, Error> {
    prepare_boot_keys()?;
    let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
    match poll_boot_keys(&mut cx) {
        Poll::Ready(result) => result?,
        Poll::Pending => return Err(Error::Busy),
    }
    let Some(mut owner) = BOOT_OWNER.try_lock() else {
        return Err(Error::Busy);
    };
    owner
        .as_mut()
        .ok_or(Error::DeviceGone)?
        .step_group_network(link, tx)
}
/// The group-link analogue of `boot_receive_current`.
pub(crate) fn boot_group_receive_current(
    link: crate::mt7921::vif_slots::Link,
    epoch: u64,
) -> Result<bool, Error> {
    let Some(owner) = BOOT_OWNER.try_lock() else {
        return Ok(false);
    };
    owner
        .as_ref()
        .map_or(Ok(false), |owner| owner.group_receive_current(link, epoch))
}
/// The retained boot owner's group link and its role state.
pub(crate) fn boot_group_link() -> Option<(crate::mt7921::vif_slots::Link, State)> {
    let owner = BOOT_OWNER.try_lock()?;
    let owner = owner.as_ref()?;
    Some((owner.group_link()?, owner.group_state()?))
}

/// Reserve the concurrent P2P GO vif `vif` with own address `own` on the
/// retained boot owner (no native command).
pub(crate) fn open_boot_go(vif: crate::mt7921::vif_slots::Vif, own: [u8; 6]) -> Result<(), Error> {
    let Some(mut owner) = BOOT_OWNER.try_lock() else {
        return Err(Error::Busy);
    };
    owner.as_mut().ok_or(Error::DeviceGone)?.open_go(vif, own)
}
/// Close an idle reserved GO that never sent a native command.
pub(crate) fn close_boot_go() -> Result<(), Error> {
    let Some(mut owner) = BOOT_OWNER.try_lock() else {
        return Err(Error::Busy);
    };
    owner.as_mut().ok_or(Error::DeviceGone)?.close_go()
}
/// START the GO beside the home station (`mt7921_add_interface` +
/// `mt7921_start_ap` on the GO vif, no reset); returns its receive epoch.
pub(crate) async fn start_boot_go(
    authority: Arc<narf_wireless::ap_control::ApControlAuthority>,
    config: narf_wireless::ApConfig,
    settings: narf_wireless::ApStartSettings,
) -> Result<u64, Error> {
    boot_owner_call!(owner => owner.start_go(authority, config, settings))
}
/// STOP the GO (`mt7921_stop_ap` + `mt792x_remove_interface`, no reset).
pub(crate) async fn stop_boot_go() -> Result<(), Error> {
    boot_owner_call!(owner => owner.stop_go())
}
/// One AP control request on the GO (beacon, stations, keys, TX).
pub(crate) async fn boot_go_request(
    authority: Arc<narf_wireless::ap_control::ApControlAuthority>,
    request: boot_ap::Request,
) -> Result<boot_ap::Reply, Error> {
    boot_owner_call!(owner => owner.go_request(authority, request))
}
/// One bounded GO data step after pending home/group key work, exactly as
/// `step_boot_group_network`.
pub(crate) fn step_boot_go_network(
    tx: Option<&[u8]>,
) -> Result<(PacketStep, Vec<ApRxEvent>), Error> {
    prepare_boot_keys()?;
    let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
    match poll_boot_keys(&mut cx) {
        Poll::Ready(result) => result?,
        Poll::Pending => return Err(Error::Busy),
    }
    let Some(mut owner) = BOOT_OWNER.try_lock() else {
        return Err(Error::Busy);
    };
    owner.as_mut().ok_or(Error::DeviceGone)?.step_go_network(tx)
}
/// Whether a GO batch epoch is still current (`go_receive_current`).
pub(crate) fn boot_go_receive_current(epoch: u64) -> Result<bool, Error> {
    let Some(owner) = BOOT_OWNER.try_lock() else {
        return Ok(false);
    };
    owner
        .as_ref()
        .map_or(Ok(false), |owner| owner.go_receive_current(epoch))
}
/// The retained boot owner's GO vif and role state.
pub(crate) fn boot_go_state() -> Option<(crate::mt7921::vif_slots::Vif, State)> {
    let owner = BOOT_OWNER.try_lock()?;
    owner.as_ref()?.go_state()
}
/// The GO's peer addresses.
pub(crate) fn boot_go_stations() -> Vec<[u8; 6]> {
    BOOT_OWNER
        .try_lock()
        .and_then(|owner| owner.as_ref().map(|owner| owner.go_station_macs()))
        .unwrap_or_default()
}

/// Recovery owns its transport across polls, including after caller
/// cancellation. Carrier must be closed before this operation is requested.
pub async fn recover_boot_radio(expected_mac: [u8; 6]) -> Result<(), Error> {
    if expected_mac == [0; 6] || expected_mac[0] & 1 != 0 {
        return Err(Error::Bounds);
    }
    reset_boot_transport(Some(expected_mac)).await
}

/// System-PM prepare phase for the retained radio. The started transition
/// owns the transport across caller cancellation, like reset. With no
/// claimed transport the parked PCI function has nothing to quiesce.
pub async fn suspend_boot_radio() -> Result<(), Error> {
    retained_owner_work(true, |mut transport| {
        alloc::boxed::Box::pin(async move {
            let result = transport.suspend().await;
            (transport, result)
        })
    })
    .await
}

/// Resume after [`suspend_boot_radio`]. A failed low-power exit falls back
/// to verified reset recovery with the same identity; the station is idle.
pub async fn resume_boot_radio(expected_mac: [u8; 6]) -> Result<(), Error> {
    if expected_mac == [0; 6] || expected_mac[0] & 1 != 0 {
        return Err(Error::Bounds);
    }
    retained_owner_work(true, move |mut transport| {
        alloc::boxed::Box::pin(async move {
            let result = match transport.state() {
                State::Suspended(_) | State::WowSuspended { .. } => {
                    transport.resume(expected_mac).await.map(|_| ())
                }
                State::Failed { .. } | State::Running(_) => {
                    transport.recover(expected_mac).await.map(|_| ())
                }
                // A suspend that never completed left the radio usable.
                _ => Ok(()),
            };
            (transport, result)
        })
    })
    .await
}

async fn retained_owner_work(
    absent_ok: bool,
    start: impl FnOnce(Transport) -> KeyFuture<Transport>,
) -> Result<(), Error> {
    // An earlier failed rekey/reset reported its error; its owner returns
    // to BOOT_OWNER before a new retained transition may start.
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
        let Some(transport) = owner.take() else {
            return if absent_ok {
                Ok(())
            } else {
                Err(Error::DeviceGone)
            };
        };
        *work = Some(KeyWork {
            future: Some(start(transport)),
            completed: None,
        });
    }
    finish_boot_keys().await
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
    BOOT_STARTED.store(true, core::sync::atomic::Ordering::Release);
    if crate::module_host::owns_discovery() {
        return InitResult::Ok;
    }
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
static NEXT_RECEIVE_EPOCH: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

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
    Cancelled,
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
    Suspend,
    WowSuspend,
    Resume,
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
    MonitorStart,
    MonitorStop,
    ApStart,
    ApStop,
    ApPeer,
    P2pDeviceStart,
    P2pDeviceStop,
    P2pRocAcquire,
    P2pRocExpire,
    P2pManagementTx,
}
/// Firmware observations, not an operational WLAN interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub version: [u8; 10],
    pub build_date: [u8; 15],
    pub patch_already_loaded: bool,
    pub bytes_transferred: usize,
}

/// Actual firmware association retained solely for autonomous wake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WakeAssociation {
    pub peer: [u8; 6],
    pub channel: u8,
    pub aid: u16,
}
/// Session state survives cancellation of its borrowed run future.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Running(Stage),
    Ready(Report),
    RadioReady(RadioInfo),
    ScanReady(RadioInfo),
    /// Native P2P-device DEV/BSS receipts. No RF grant, ordinary carrier
    /// or Ethernet/controlled-port permission follows from this state.
    P2pDevice(RadioInfo),
    Associated {
        info: RadioInfo,
        peer: [u8; 6],
        channel: u8,
        aid: u16,
    },
    /// Native BSS, group WTBL and beacon template acknowledged. Host
    /// carrier/peer admission requires the separate current interface owner.
    AccessPoint {
        info: RadioInfo,
        frequency_mhz: u32,
    },
    /// Native passive sniffer acknowledged; ordinary station RX/TX stays closed.
    Monitor {
        info: RadioInfo,
        channel: narf_wireless::monitor::Channel,
    },
    /// PCIe low-power handoff completed; firmware owns LPCTL and DMA is off.
    Suspended(RadioInfo),
    /// Firmware association/offloads retained for wake; host RX/TX closed.
    WowSuspended {
        info: RadioInfo,
        association: Option<WakeAssociation>,
        target: narf_power::system_pm::SystemSleepState,
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
    release_features: Result<Option<super::fw_features::Features>, super::fw_features::Error>,
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
            release_features: super::fw_features::parse(ram),
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
    /// Optional WM release metadata, retained from this immutable artifact.
    /// Missing metadata gives no CNM capability; malformed metadata remains
    /// distinguishable without breaking legacy firmware boot. This grants
    /// no started device, channel, packet or RF permission.
    pub fn cnm_capability(&self) -> Result<bool, Error> {
        self.release_features
            .map(|feature| feature.is_some_and(|feature| feature.cnm()))
            .map_err(|_| Error::InvalidFirmware)
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

/// Immutable admission facts at the native DMA-to-owned-copy boundary.
/// A later port opening cannot authorize a copy made while the port was shut.
/// In AP mode this flag denotes the BSS capture binding only: the native
/// WCID, per-peer association/port and current software CCMP proof are also
/// required. Every AP peer/key/port change renews this global capture epoch.
#[derive(Debug, PartialEq, Eq)]
struct CapturedData {
    bytes: Vec<u8>,
    epoch: u64,
    port_open: bool,
}

trait Backend {
    fn close_p2p_capture(&mut self) {}
    fn configure_p2p_capture(
        &mut self,
        spec: Option<p2p_management_capture::Spec>,
    ) -> Result<(), Error> {
        if spec.is_some() {
            Err(Error::UnsupportedFirmware)
        } else {
            Ok(())
        }
    }
    fn receive_p2p_management(
        &mut self,
    ) -> Result<Option<p2p_management_capture::Captured>, Error> {
        Err(Error::UnsupportedFirmware)
    }
    /// Actual hardware chip ID; zero means no identity proof in a pure model.
    /// Wider chip-specific profiles must not infer this from firmware max_bw.
    fn chip_id(&self) -> Result<u16, Error> {
        Ok(0)
    }
    /// Protocol nonce entropy is fallible; deterministic fixtures override this
    /// boundary, while the native backend always requires the architectural RNG.
    fn random_bytes(&mut self, out: &mut [u8]) -> Result<(), Error> {
        narf_crypto::try_fill_random_bytes(out).map_err(|_| Error::EntropyUnavailable)
    }
    fn progress(&mut self, _stage: Stage) {}
    fn now_ns(&self) -> u64;
    fn check(&self) -> Result<(), Error>;
    fn regulatory_domain(&self) -> Result<Arc<narf_wireless::reg::RegulatoryDomain>, Error> {
        narf_wireless::reg::db::snapshot().ok_or(Error::Authority)
    }
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
    fn receive_data_captured(&mut self) -> Result<Option<CapturedData>, Error>;
    /// Infallibly close host admission before any key/owner transition can wait.
    fn close_receive_capture(&mut self, epoch: u64);
    /// Preserve closed copies and drain the already-completed native prefix
    /// before changing the copy-time admission state. This is not a firmware
    /// key-retirement or MAC/FIFO quiescence proof.
    fn open_receive_capture(&mut self, epoch: u64) -> Result<(), Error>;
    /// A current native completed-RX-ring observation, including host-queued
    /// normal/forwarded frames. An empty decoded-frame result is insufficient.
    /// This does not prove MAC/FIFO or in-flight firmware quiescence.
    fn receive_idle(&self) -> Result<bool, Error>;
    fn release(&mut self) -> Result<(), Error>;
    /// `mt7921_pci_suspend`: after the busy poll, clear TX/RX DMA_EN and
    /// mask host interrupts. Ring configuration is retained for resume.
    fn suspend_dma(&mut self) -> Result<(), Error>;
    /// `__mt792x_mcu_fw_pmctrl`: return LPCTL ownership to firmware.
    fn request_firmware_own(&mut self) -> Result<(), Error>;
    fn firmware_owned(&mut self) -> Result<bool, Error>;
    fn prepare_wake_route(
        &mut self,
        _target: narf_power::system_pm::SystemSleepState,
    ) -> Result<(), Error> {
        Err(Error::UnsupportedFirmware)
    }
    fn arm_wake_route(
        &mut self,
        _target: narf_power::system_pm::SystemSleepState,
    ) -> Result<(), Error> {
        Err(Error::UnsupportedFirmware)
    }
    fn wake_power_settled(&self) -> bool {
        true
    }
    fn enter_wake_d3hot(&mut self) -> Result<(), Error> {
        Err(Error::UnsupportedFirmware)
    }
    fn verify_wake_d3hot(&mut self) -> Result<(), Error> {
        Err(Error::UnsupportedFirmware)
    }
    fn begin_wake_d0(&mut self) -> Result<bool, Error> {
        Ok(false)
    }
    fn verify_wake_d0(&mut self) -> Result<(), Error> {
        Err(Error::UnsupportedFirmware)
    }
    fn disarm_wake_route(&mut self) -> Result<(), Error> {
        Ok(())
    }
    /// Restore memory decoding after a platform power transition, without
    /// bus mastering (Linux PCI core config restore precedes driver resume).
    fn restore_bus(&mut self) -> Result<(), Error>;
    /// `mt792x_dma_need_reinit`: WFDMA lost `DUMMY_CR.NEED_REINIT`.
    fn dma_needs_reinit(&mut self) -> Result<bool, Error>;
    /// `mt792x_wpdma_reset(dev, false)`: caller proved DMA disabled and idle;
    /// retire ring ownership and reprogram the same retained rings.
    fn reinit_dma(&mut self) -> Result<(), Error>;
    /// Re-enable retained rings: bus mastering then TX/RX DMA_EN.
    fn resume_dma(&mut self) -> Result<(), Error>;
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
    fn pause_ap_timing(&mut self) -> Result<(), Error>;
    fn finish_ap_timing(&mut self, five: bool, short_slot: bool) -> Result<(), Error>;
    fn clear_wtbl(&mut self, index: u8) -> Result<(), Error>;
    fn wtbl_idle(&mut self) -> Result<bool, Error>;
    /// Station management on `vif` (TXD1 `OWN_MAC`, mt76_connac2_mac_write_txwi);
    /// `wcid` is that vif's peer or BMC WCID.
    fn submit_management(
        &mut self,
        vif: crate::mt7921::vif_slots::Vif,
        frame: &[u8],
        wcid: u16,
        rate: crate::mt7921::association::LegacyRate,
    ) -> Result<(), Error>;
    fn management_complete(
        &mut self,
    ) -> Result<Option<crate::mt7921::packet_tx::Completion>, Error>;
    /// One 802.11 data fragment (`packet_tx::fragment`) on the data ring, to
    /// `link`'s peer WCID with its vif's OWN_MAC/WMM set.
    fn submit_fragment(
        &mut self,
        link: crate::mt7921::vif_slots::Link,
        frame: &[u8],
    ) -> Result<(), Error>;
    /// Station data to `link`'s peer WCID; the TXD's OWN_MAC and AC queue
    /// WMM set follow its vif (`packet_tx::on_vif`). `Link::HOME` is the
    /// historical WCID 1 / OMAC0 / WMM0 descriptor.
    fn submit_data(
        &mut self,
        link: crate::mt7921::vif_slots::Link,
        frame: &[u8],
        protected: bool,
        qos: bool,
    ) -> Result<(), Error>;
    /// Raw AP frame on the AP BSS `vif`, with no hardware encryption key or
    /// header translation (`ap_packet::descriptor_on`).
    fn submit_ap_frame(
        &mut self,
        vif: crate::mt7921::vif_slots::Vif,
        frame: &[u8],
        wcid: u8,
        rate: crate::mt7921::association::LegacyRate,
    ) -> Result<(), Error>;
    fn arm_ap_management(
        &mut self,
        vif: crate::mt7921::vif_slots::Vif,
        wcid: u8,
    ) -> Result<(), Error>;
    fn submit_ap_management(
        &mut self,
        vif: crate::mt7921::vif_slots::Vif,
        frame: &[u8],
        wcid: u8,
        rate: crate::mt7921::association::LegacyRate,
    ) -> Result<(), Error>;
    fn poll_ap_management_ack(&mut self) -> Result<Option<bool>, Error>;
    fn arm_p2p_management(
        &mut self,
        _vif: crate::mt7921::vif_slots::Vif,
        _tid: u8,
    ) -> Result<(), Error> {
        Err(Error::UnsupportedFirmware)
    }
    fn submit_p2p_management(
        &mut self,
        _frame: &[u8],
        _vif: crate::mt7921::vif_slots::Vif,
        _rate: crate::mt7921::association::LegacyRate,
    ) -> Result<(), Error> {
        Err(Error::UnsupportedFirmware)
    }
    fn poll_p2p_management_ack(&mut self) -> Result<Option<bool>, Error> {
        Err(Error::UnsupportedFirmware)
    }
    fn submit_data_pipelined(
        &mut self,
        link: crate::mt7921::vif_slots::Link,
        frame: &[u8],
        protected: bool,
        qos: bool,
    ) -> Result<(), Error> {
        self.submit_data(link, frame, protected, qos)
    }
    fn submit_data_aggregated(
        &mut self,
        _link: crate::mt7921::vif_slots::Link,
        _frame: &[u8],
        _protected: bool,
    ) -> Result<(), Error> {
        Err(Error::UnsupportedFirmware)
    }
    /// Reserve a currently free, non-quarantined host-TXS PID after every older native packet
    /// has DMA and TX_FREE terminal receipts. The next true user MPDU (or
    /// final fragment) on this TID acquires that retained sample owner.
    fn arm_transmit_sequence(&mut self, _tid: u8) -> Result<(), Error> {
        Err(Error::UnsupportedFirmware)
    }
    fn transmit_sequence_published(&self, _tid: u8) -> bool {
        false
    }
    fn poll_transmit_sequence(&mut self, _tid: u8) -> Result<Option<u16>, Error> {
        Err(Error::UnsupportedFirmware)
    }
    fn cancel_transmit_sequence(&mut self) {}

    /// Linux `wcid->amsdu`: hardware TX A-MSDU (TXD7 HW_AMSDU) for this peer.
    fn set_hw_amsdu(&mut self, _enabled: bool) {}
    /// QoS data on user priority `tid` 1..=7 (TID 0 uses the BE paths above).
    /// The non-BA path; agreement eligibility is supplied separately.
    fn submit_data_tid(
        &mut self,
        _link: crate::mt7921::vif_slots::Link,
        _frame: &[u8],
        _protected: bool,
        _tid: u8,
        _pipelined: bool,
    ) -> Result<(), Error> {
        Err(Error::UnsupportedFirmware)
    }
    /// QoS DATA under the independently completed originator agreement for
    /// `tid`. No BA or sequence authority follows from calling this method.
    fn submit_data_tid_aggregated(
        &mut self,
        link: crate::mt7921::vif_slots::Link,
        frame: &[u8],
        protected: bool,
        tid: u8,
    ) -> Result<(), Error> {
        if tid == 0 {
            self.submit_data_aggregated(link, frame, protected)
        } else {
            Err(Error::UnsupportedFirmware)
        }
    }
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

/// One station-mode vif's association owner, keyed by its native
/// [`Link`](crate::mt7921::vif_slots::Link) identity. Linux keeps this
/// state per `mt792x_vif` / `mt792x_sta` (mt792x.h): the peer WCID, its BA
/// sessions, WMM and PHY profiles and the RX reorder/defrag caches.
#[derive(Debug)]
struct StationLink {
    link: crate::mt7921::vif_slots::Link,
    security: Option<join::StationSecurity>,
    management_rate: crate::mt7921::association::LegacyRate,
    used_tids: u8,
    tx_ba: tx_ba::Owner,
    tx_restart: Option<tx_ba_restart::Request>,
    peer_lost: bool,
    /// Signal and receive rate of the frames from this link's AP, for
    /// NL80211_CMD_GET_STATION; reset with each association.
    link_stats: crate::mt7921::link_stats::LinkStats,
    /// cfg80211 `wdev->ps` as the owner should apply it, and the power
    /// state the firmware BSS last took (`UNI_BSS_INFO_PS`; awake after
    /// each association).
    ps_wanted: bool,
    ps_applied: bool,
    /// The regulatory policy snapshot the grant and the firmware channel
    /// domain / power limits were last programmed from.
    applied_policy: Option<Arc<narf_wireless::reg::RegulatoryDomain>>,
    /// The AP this link is roaming away from: the next join sends a
    /// Reassociation Request naming it (consumed by that join).
    reassociate_from: Option<[u8; 6]>,
    /// The AP's announced channel switch and when it takes effect
    /// (mac80211 `csa` state of the managed interface).
    csa: Option<(crate::mt7921::association::ChannelSwitch, u64)>,
    /// Channel Switch Mode 1 is in force: no data until the switch.
    csa_block_tx: bool,
    bss: Option<ScanBss>,
    /// This link's group role captured at join; retained for the exact
    /// disconnect record of that association (Linux `vif->p2p` is fixed per
    /// vif type).
    network: crate::mt7921::p2p_wire::Network,
    permission: Option<crate::mt7921::association::TxPermission>,
    wmm: Option<crate::mt7921::association::wmm::Parameters>,
    wmm_pending: Option<crate::mt7921::association::wmm::Parameters>,
    ht20_rx: Option<amsdu::Receiver>,
    ht20_profile: Option<crate::mt7921::ht20::Profile>,
    vht_profile: Option<crate::mt7921::vht::Profile>,
    he_profile: Option<crate::mt7921::he::Profile>,
    ap_phy: Option<narf_wireless::association::phy::ApElements>,
    control_pending: VecDeque<Vec<u8>>,
    /// The remaining software fragments of the MSDU in flight (each one
    /// waits for the previous fragment's terminal completion).
    tx_fragments: VecDeque<Vec<u8>>,
    rx_ba: ba::Owner,
    received_msdu: VecDeque<Vec<u8>>,
    rx_fragments: fragment::Cache,
    /// Captured native packets whose RXD WCID is this link's peer, drained
    /// from the shared RX ring by the other station owner (Linux
    /// `mt76_rx` -> `mt792x_rx_get_wcid` -> per-`mt792x_sta` delivery).
    demuxed: VecDeque<CapturedData>,
    /// This owner's receive floor: the shared capture epoch of its last
    /// key/association fence. A copy captured before it is never this
    /// owner's (the other owner's fences do not move it).
    epoch: u64,
    /// Set by this owner's fence; the next time it becomes receive-current
    /// next to another owner it moves its floor past every copy captured
    /// while the shared capture stayed open only for that other owner.
    fenced: bool,
    /// Terminal TX statuses of this owner's data entries retired by the
    /// other station owner's waits (`data_pending` is one device FIFO).
    tx_credit: VecDeque<u8>,
}
/// The concurrent group vif's station owner and its own role state
/// (`State::RadioReady` = WCID only, `ScanReady` = DEV_INFO/BSS published,
/// `Associated`/`Failed` as for the home role). `info.capabilities.mac` is
/// the group vif's own address.
#[derive(Debug)]
struct GroupOwner {
    station: StationLink,
    state: State,
}
impl StationLink {
    fn new(link: crate::mt7921::vif_slots::Link) -> Self {
        Self {
            link,
            security: None,
            management_rate: crate::mt7921::association::LegacyRate::ONE_MBPS,
            used_tids: 0,
            tx_ba: tx_ba::Owner::default(),
            tx_restart: None,
            peer_lost: false,
            link_stats: crate::mt7921::link_stats::LinkStats::default(),
            ps_wanted: false,
            ps_applied: false,
            applied_policy: None,
            reassociate_from: None,
            csa: None,
            csa_block_tx: false,
            bss: None,
            network: crate::mt7921::p2p_wire::Network::Infrastructure,
            permission: None,
            wmm: None,
            wmm_pending: None,
            ht20_rx: None,
            ht20_profile: None,
            vht_profile: None,
            he_profile: None,
            ap_phy: None,
            control_pending: VecDeque::new(),
            tx_fragments: VecDeque::new(),
            rx_ba: ba::Owner::default(),
            received_msdu: VecDeque::new(),
            rx_fragments: fragment::Cache::default(),
            demuxed: VecDeque::new(),
            epoch: 0,
            fenced: false,
            tx_credit: VecDeque::new(),
        }
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
    data_pending: group_link::DataPending,
    /// The home vif's station owner (BSS0, peer WCID 1).
    station: StationLink,
    /// A concurrent P2P group vif's station owner (Linux mt7921 keeps one
    /// `mt792x_vif` per vif); opened by `open_group_link`. While a group
    /// operation runs (`enter_group`) it holds the swapped-out home owner.
    group: Option<GroupOwner>,
    /// A concurrent P2P GO vif's AP owner (`go_link`); while a GO
    /// operation runs (`enter_go`) it holds the swapped-out home role.
    go: Option<go_link::GoOwner>,
    /// Peer WCIDs owned by station links (Linux `dev->wcid_mask`).
    wtbl: crate::mt7921::vif_slots::Wtbl,
    /// The wiphy fragmentation threshold (`u32::MAX` = off).
    frag_threshold: u32,
    /// The home station's SAE PMKSA cache.
    pmksa: crate::mt7921::pmksa::Cache,
    receive_epoch: u64,
    /// Original copy-time native packets handed from the scan collector to
    /// the associated station's parsers; never re-stamped at delivery.
    scan_packets: VecDeque<CapturedData>,
    /// During an associated scan, RX consumes only the hand-off queue so
    /// station service cannot swallow off-channel scan observations.
    scanning: bool,
    ap_owner: Option<ap::Owner>,
    p2p_owner: Option<p2p::Owner>,
    /// PHY-global CNM sequence survives independent wdev stop/recreation.
    p2p_next: u8,
    // Keep retired AP temporal-key evidence across verified role resets.
    ap_keys: ap_crypto::Keys,
    wow_config: Option<narf_wireless::WowlanConfig>,
    wow_nlo: Option<Arc<scan::nlo::Plan>>,
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
            data_pending: group_link::DataPending::default(),
            station: StationLink::new(crate::mt7921::vif_slots::Link::HOME),
            group: None,
            go: None,
            wtbl: crate::mt7921::vif_slots::Wtbl::default(),
            frag_threshold: u32::MAX,
            pmksa: crate::mt7921::pmksa::Cache::default(),
            receive_epoch: 0,
            scan_packets: VecDeque::new(),
            scanning: false,
            ap_owner: None,
            p2p_owner: None,
            p2p_next: 1,
            ap_keys: ap_crypto::Keys::default(),
            wow_config: None,
            wow_nlo: None,
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
        self.wait_split(ms, |backend, _, _| f(backend)).await
    }
    /// `wait` whose poll also borrows the swapped-out station owner, so a
    /// station wait can hand the other owner's frames and TX completions
    /// to it instead of discarding them (`group_link::route_station_rx`).
    async fn wait_split<T>(
        &mut self,
        ms: u64,
        mut f: impl FnMut(
            &mut B,
            &mut Option<GroupOwner>,
            &mut Option<go_link::GoOwner>,
        ) -> Result<Option<T>, Error>,
    ) -> Result<T, Error> {
        let start = self.backend.now_ns();
        poll_fn(|cx| {
            // The AP can already beacon while its last command receipt is
            // pending. Recheck the actual request and RF owner on every
            // native wait poll; cleanup/recovery uses its own device grant.
            if matches!(self.state, State::Running(Stage::ApStart | Stage::ApPeer)) {
                if let Some(owner) = &self.ap_owner {
                    if owner
                        .pending
                        .as_ref()
                        .is_none_or(|grant| grant.current().is_err())
                    {
                        return Poll::Ready(Err(Error::Authority));
                    }
                    if owner.identity.current().is_err() {
                        return Poll::Ready(Err(Error::Authority));
                    }
                    if let Err(error) = self.backend.check_tx_permission(owner.plan.permission) {
                        return Poll::Ready(Err(error));
                    }
                }
            }
            if matches!(self.state, State::Running(Stage::P2pDeviceStart)) {
                if let Some(owner) = self.p2p_owner.as_ref() {
                    if owner
                        .pending
                        .as_ref()
                        .is_none_or(|authority| authority.current().is_err())
                        || owner.identity.current().is_err()
                    {
                        return Poll::Ready(Err(Error::Authority));
                    }
                }
            }
            if matches!(self.state, State::Running(Stage::P2pRocAcquire)) {
                if let Err(error) = self.check_p2p_roc_pending() {
                    return Poll::Ready(Err(error));
                }
            }
            if matches!(self.state, State::Running(Stage::P2pManagementTx)) {
                if let Err(error) = self.check_p2p_management_tx() {
                    return Poll::Ready(Err(error));
                }
            }
            if matches!(self.state, State::Running(Stage::P2pRocExpire)) {
                if let Some(implicit) = self
                    .p2p_owner
                    .as_ref()
                    .and_then(|owner| owner.management.implicit)
                {
                    if let Err(error) =
                        self.check_p2p_management_home(implicit.plan.home, implicit.home)
                    {
                        return Poll::Ready(Err(error));
                    }
                }
            }
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
            match f(&mut self.backend, &mut self.group, &mut self.go) {
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
        let _ap_request = self
            .ap_owner
            .as_ref()
            .and_then(|owner| owner.pending.clone());
        let _p2p_request = self
            .p2p_owner
            .as_ref()
            .and_then(|owner| owner.pending.clone());
        if self.p2p_owner.is_some() {
            let result = self.stop_p2p_device_owned().await;
            if self.p2p_owner.is_some() {
                return result;
            }
        }
        // WFDMA shutdown alone cannot stop autonomous firmware beacons.
        // Retain the AP owner unless its verified reset actually completes.
        if self.ap_owner.is_some() {
            let result = self.stop_ap_owned().await;
            if self.ap_owner.is_some() {
                return result;
            }
        }
        self.boot_started = None;
        self.station.rx_ba.fence();
        self.station.tx_ba.fence();
        self.station.security = None;
        self.station.permission = None;
        self.station.ht20_rx = None;
        self.station.ht20_profile = None;
        self.station.vht_profile = None;
        self.station.he_profile = None;
        self.station.ap_phy = None;
        self.station.received_msdu.clear();
        self.station.rx_fragments.clear();
        self.stage(Stage::Shutdown);
        let result = async {
            self.normalize_wake_bus().await?;
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
