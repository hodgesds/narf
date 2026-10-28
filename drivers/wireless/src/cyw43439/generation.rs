// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained owner of one function's published FullMAC shell across its
//! transport generations, and the teardown that ends it.
//!
//! Linux v7.2 `brcmfmac/pcie.c::brcmf_pcie_remove` marks the bus down,
//! cancels reset work (`brcmf_bus_cancel_reset_work`), detaches the
//! common layer (`brcmf_detach`), releases the IRQ and only then the
//! scratch and ring buffers. Here the shell withdraws first and the
//! transport generation is stopped and released under the station mutex;
//! the published memory is freed only behind a complete stop proof.
//!
//! Linux v7.2 `core.c::brcmf_fw_crashed` (FWHALT) schedules
//! `brcmf_core_bus_reset` -> `pcie.c::brcmf_pcie_reset`: `brcmf_detach`,
//! IRQ and ring release, `brcmf_pcie_reset_device`, a fresh firmware
//! download (`brcmf_pcie_setup`) and `brcmf_attach`, which registers a new
//! netdev. [`Generation::recover`] is that sequence over a retained owner:
//! the old shell withdraws (its netdev retired, not unregistered), the
//! transport stops behind a proof, resets and reboots in place, and the
//! fresh generation is re-initialized (`Station::initialize_live` through
//! the publisher) and republished under the same name (`rebind_name`),
//! then rejoins the retained association.
use super::*;
use core::{future::Future, pin::Pin};

/// Publishes a fresh, rebooted transport generation as a new shell under
/// the retired name (production: `attach_runtime`).
pub type Publish<R> = Box<
    dyn Fn(&'static str, R) -> Pin<Box<dyn Future<Output = Result<Arc<Device<R>>, Error>> + Send>>
        + Send
        + Sync,
>;
/// Generations one function may reset through before it stays terminal
/// (a firmware that halts on every boot must not loop forever).
pub const MAX_RESETS: u32 = 64;

/// Outcome of [`Generation::remove`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Removal {
    /// No transport generation was attached.
    Absent,
    /// A complete stop proof released every published mapping.
    Reclaimed,
    /// The stop was unproven: published memory stays pinned.
    Pinned,
}
impl Removal {
    /// Whether nothing remains mapped for the device.
    pub fn released(self) -> bool {
        self != Self::Pinned
    }
}

/// The current shell of one function. Removal and every generation swap
/// serialize on `current`, so a removal observes either the old shell or
/// the replacement, never a half-published one.
pub struct Generation<R: Fullmac> {
    current: Mutex<Option<Arc<Device<R>>>>,
    /// `bus_if->removing`: no later generation may be published.
    removed: AtomicBool,
    /// A generation retired without a proof: its mappings stay pinned.
    pinned: AtomicBool,
    resets: core::sync::atomic::AtomicU32,
    publish: Option<Publish<R>>,
}
impl<R: Fullmac> core::fmt::Debug for Generation<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FullmacGeneration")
            .field("removed", &self.removed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}
impl<R: Fullmac + 'static> Generation<R> {
    pub fn new(device: Arc<Device<R>>) -> Self {
        Self {
            current: Mutex::new(Some(device)),
            removed: AtomicBool::new(false),
            pinned: AtomicBool::new(false),
            resets: core::sync::atomic::AtomicU32::new(0),
            publish: None,
        }
    }
    /// A generation owner that can reset and republish the transport.
    pub fn with_publisher(device: Arc<Device<R>>, publish: Publish<R>) -> Self {
        Self {
            publish: Some(publish),
            ..Self::new(device)
        }
    }
    /// Completed transport resets.
    pub fn resets(&self) -> u32 {
        self.resets.load(Ordering::Acquire)
    }
    /// Reset the transport and republish the station (see module docs).
    /// Serialized with [`Self::remove`]: a removal requested meanwhile is
    /// honoured before the fresh generation is published, and that
    /// generation is then stopped and released instead. On any failure the
    /// function stays terminal with no published shell.
    pub async fn recover(&self) -> Result<(), Error> {
        let publish = self.publish.as_ref().ok_or(Error::Unsupported)?;
        let mut current = self.current.lock().await;
        if self.removed() {
            return Err(Error::Busy);
        }
        let old = current.take().ok_or(Error::Failed)?;
        old.withdraw();
        let request = old.lifecycle.request.lock().take();
        let mut fresh = {
            let mut state = old.state.lock().await;
            state.clear_transmit();
            state.station.bssid = None;
            old.power_save.store(2, Ordering::Release);
            let runtime = &mut state.station.runtime;
            if runtime.stop_transport().await.is_err() {
                if !runtime.release_transport() {
                    self.pinned.store(true, Ordering::Release);
                }
                return Err(Error::Failed);
            }
            if self.resets.load(Ordering::Acquire) >= MAX_RESETS {
                runtime.release_transport();
                return Err(Error::Failed);
            }
            if let Err(error) = runtime.reset_transport().await {
                if !runtime.release_transport() {
                    self.pinned.store(true, Ordering::Release);
                }
                return Err(error);
            }
            runtime.take_generation().ok_or(Error::Failed)?
        };
        self.resets.fetch_add(1, Ordering::AcqRel);
        if self.removed() {
            // `brcmf_bus_cancel_reset_work`: removal won the race. The fresh
            // generation never publishes; stop and release it now.
            let proved = fresh.stop_transport().await.is_ok();
            if !(fresh.release_transport() && proved) {
                self.pinned.store(true, Ordering::Release);
            }
            return Err(Error::Busy);
        }
        let name = narf_net::iface::rebind_name(&old.name).ok_or(Error::Busy)?;
        drop(old);
        let device = match publish(name, fresh).await {
            Ok(device) => device,
            Err(error) => {
                // The refused generation was dropped without a stop proof.
                self.pinned.store(true, Ordering::Release);
                return Err(error);
            }
        };
        if let Some(request) = request {
            // The fresh firmware has no scan results: rediscover the exact
            // retained BSS on its channel, then join it again. The rejoin
            // may fail (AP gone); the shell stays published and the
            // operator's next connect proceeds as usual.
            let scan = ScanRequest {
                ssids: alloc::vec![request.ssid.clone()],
                frequencies_mhz: alloc::vec![request.frequency_mhz],
                channels: alloc::vec![request.channel],
                active: false,
                random_mac: None,
                colocated_6ghz: false,
                duration_tu: None,
                duration_mandatory: false,
                extra_ies: Vec::new(),
            };
            let found = Box::pin(WirelessNetIface::scan(&*device, scan))
                .await
                .is_ok_and(|bss| bss.iter().any(|bss| bss.bssid == request.bssid));
            if found {
                let _ = Box::pin(WirelessNetIface::associate(&*device, request)).await;
            }
        }
        *current = Some(device);
        Ok(())
    }
    /// Watch the current generation and reset it when its transport turns
    /// terminal (FWHALT, lost power, fatal protocol/access error). Ends on
    /// removal or when a reset fails.
    pub async fn supervise(self: Arc<Self>) {
        loop {
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(100_000_000)).await;
            if self.removed() {
                return;
            }
            let failed = match self.current.try_lock() {
                Some(current) => match current.as_ref() {
                    Some(device) => device.transport_failed(),
                    None => return,
                },
                None => continue,
            };
            if !failed {
                continue;
            }
            match Box::pin(self.recover()).await {
                Ok(()) => narf_console::klog!(
                    "FullMAC: transport reset, generation {} published\n",
                    self.resets()
                ),
                Err(error) => {
                    narf_console::klog!("FullMAC: transport reset failed: {:?}\n", error);
                    return;
                }
            }
        }
    }
    pub fn removed(&self) -> bool {
        self.removed.load(Ordering::Acquire)
    }
    /// The current shell, if any (it may be withdrawn).
    pub fn current(&self) -> Option<Arc<Device<R>>> {
        self.current.try_lock().and_then(|current| current.clone())
    }
    /// Linux `brcmf_pcie_remove` for the retained owner: no later
    /// generation may start, then the current shell is withdrawn and its
    /// transport stopped and released.
    pub async fn remove(&self) -> Removal {
        self.removed.store(true, Ordering::Release);
        let mut current = self.current.lock().await;
        let Some(device) = current.take() else {
            return if self.pinned.load(Ordering::Acquire) {
                Removal::Pinned
            } else {
                Removal::Absent
            };
        };
        if device.teardown().await && !self.pinned.load(Ordering::Acquire) {
            Removal::Reclaimed
        } else {
            Removal::Pinned
        }
    }
}
