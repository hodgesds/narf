// SPDX-License-Identifier: GPL-2.0-or-later
//! Shared command/event/data seam for SDIO-BCDC and PCIe-msgbuf station owners.
//! This does not grant station authorization; set_link follows verified events.
use super::{
    ioctl::Direction,
    runtime::{Error, Event, Runtime},
    PacketTransport,
};
use alloc::vec::Vec;
use core::future::Future;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    Sdio,
    Pcie,
}
/// Linux `enum brcmf_fwvendor` (`bus.h`): the firmware branch whose
/// vendor-specific ABI (`fwvid.h` ops) the attached image implements. It is
/// fixed by the bus match table (`bcmsdh.c`/`pcie.c`), never by a reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirmwareVendor {
    /// `BRCMF_FWVENDOR_WCC`: BCM43602 PCIe and the Broadcom-ID 43439 SDIO
    /// match; SAE passwords use `BRCMF_C_SET_WSEC_PMK` + `BRCMF_WSEC_PASSPHRASE`.
    Wcc,
    /// `BRCMF_FWVENDOR_CYW`: the Cypress-ID 43439 SDIO match; SAE passwords
    /// use the `sae_password` iovar (`struct brcmf_wsec_sae_pwd_le`).
    Cyw,
}
impl FirmwareVendor {
    /// Linux `bcmsdh.c` `brcmf_sdmmc_ids` for the two 43439 SDIO identities:
    /// `BRCMF_SDIO_DEVICE(43439, WCC)` and `CYW_SDIO_DEVICE(43439, CYW)`.
    pub fn sdio(vendor: u16) -> Self {
        if vendor == 0x04b4 {
            Self::Cyw
        } else {
            Self::Wcc
        }
    }
}
pub trait Fullmac: Send {
    const FAMILY: Family;
    const EXTERNAL_CLM: bool;
    /// Exact attached chip profile supports the firmware's 5 GHz channel set.
    /// The SDIO CYW43439 profile remains 2.4 GHz only.
    const BAND_5GHZ: bool = false;
    /// Exact attached native family can qualify VHT80 from its firmware.
    /// CYW43439 has no such PHY, regardless of malformed capability replies.
    const VHT80: bool = false;
    /// Actual primary-bsscfg AP transport owner. SDIO stays conservative
    /// until its own native AP lifecycle/terminal composition is qualified.
    const PRIMARY_AP: bool = false;
    /// Actual primary native flagged-radiotap owner; SDIO keeps false until
    /// its independent firmware/BCDC/host composition is qualified.
    const PRIMARY_MONITOR: bool = false;
    fn monitor_reserve(
        &mut self,
        _prepared: crate::brcmfmac::monitor_native::Prepared,
    ) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn monitor_arm(&mut self, _armed: crate::brcmfmac::monitor_native::Armed) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn monitor_leave(
        &mut self,
        _original: &crate::brcmfmac::monitor_scope::Capture,
    ) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn pop_monitor(&mut self) -> Option<crate::brcmfmac::monitor_scope::Received> {
        None
    }
    fn monitor_control_idle(&mut self) -> Result<bool, Error> {
        Err(Error::Unsupported)
    }
    fn ap_source(&self) -> Option<crate::brcmfmac::ap_source::Source> {
        None
    }
    fn ap_enter(&mut self, _original: crate::brcmfmac::ap_scope::Capture) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    /// An actual transport publication returns an owned native terminal
    /// waiter. Dropping it requests no fabricated DMA release or ACK.
    fn ap_send(
        &mut self,
        _bytes: &[u8],
        _priority: u8,
        _original: &crate::brcmfmac::ap_scope::Capture,
    ) -> Result<crate::brcmfmac::ap_tx::Ticket, Error> {
        Err(Error::Unsupported)
    }
    /// Start actual flow retirement after the concrete AP closed host DATA.
    /// False means old native IDs/delete receipts are still owned.
    fn ap_leave(&mut self) -> Result<bool, Error> {
        Err(Error::Unsupported)
    }
    fn ap_completed_prefix(&mut self) -> Result<bool, Error> {
        Err(Error::Unsupported)
    }
    /// All actual host TX IDs have matching native terminals. This is not
    /// an assertion about the firmware's private MAC/RX-key FIFO state.
    fn ap_quiet(&mut self) -> Result<bool, Error> {
        Err(Error::Unsupported)
    }
    fn ap_retire_peer(&mut self, _peer: [u8; 6]) -> Result<bool, Error> {
        Err(Error::Unsupported)
    }
    fn command<'a>(
        &'a mut self,
        direction: Direction,
        command: u32,
        input: &'a [u8],
        maximum: usize,
    ) -> impl Future<Output = Result<Vec<u8>, Error>> + Send + 'a;
    /// Per-ifidx AP transport owners: one firmware-SME AP per firmware
    /// interface (Linux `brcmf_cfg80211_start_ap` addresses every dcmd to
    /// `ifp->ifidx`). Interface 0 is the primary methods above; a
    /// secondary ifidx is owned only through `vif_bsscfg::Bsscfg`, whose
    /// interface its owner opened. Primary ownership is unchanged by it.
    const SECONDARY_AP: bool = false;
    fn ap_enter_on(
        &mut self,
        _ifidx: u8,
        _original: crate::brcmfmac::ap_scope::Capture,
    ) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn ap_send_on(
        &mut self,
        _ifidx: u8,
        _bytes: &[u8],
        _priority: u8,
        _original: &crate::brcmfmac::ap_scope::Capture,
    ) -> Result<crate::brcmfmac::ap_tx::Ticket, Error> {
        Err(Error::Unsupported)
    }
    fn ap_leave_on(&mut self, _ifidx: u8) -> Result<bool, Error> {
        Err(Error::Unsupported)
    }
    fn ap_completed_prefix_on(&mut self, _ifidx: u8) -> Result<bool, Error> {
        Err(Error::Unsupported)
    }
    fn ap_quiet_on(&mut self, _ifidx: u8) -> Result<bool, Error> {
        Err(Error::Unsupported)
    }
    fn ap_retire_peer_on(&mut self, _ifidx: u8, _peer: [u8; 6]) -> Result<bool, Error> {
        Err(Error::Unsupported)
    }
    /// [`Self::command_ap`] addressed to secondary firmware interface
    /// `ifidx`; `blocked` is the caller's retained per-bsscfg record check.
    fn command_ap_on<'a>(
        &'a mut self,
        _ifidx: u8,
        _original: &'a crate::brcmfmac::ap_scope::Capture,
        _direction: Direction,
        _command: u32,
        _input: &'a [u8],
        _maximum: usize,
    ) -> impl Future<Output = Result<Vec<u8>, Error>> + Send + 'a {
        core::future::ready(Err(Error::Unsupported))
    }
    /// Original fixed AP Program scope reaches actual native publication.
    /// Unsupported backends deny by default. Stop/source-only cleanup uses
    /// ordinary command and never obtains new AP Program authority.
    fn command_ap<'a>(
        &'a mut self,
        _original: &'a crate::brcmfmac::ap_scope::Capture,
        _direction: Direction,
        _command: u32,
        _input: &'a [u8],
        _maximum: usize,
    ) -> impl Future<Output = Result<Vec<u8>, Error>> + Send + 'a {
        core::future::ready(Err(Error::Unsupported))
    }
    fn configure_bus(&mut self) -> impl Future<Output = Result<(), Error>> + Send;
    /// Consumed transport records, bounded per call. Positive progress may
    /// leave more RX/events beyond the budget. Zero requires an actual current
    /// FIFO/completion-ring idle observation, not an empty decoded host queue;
    /// queued events/data remain available to their pop methods.
    fn poll(&mut self) -> Result<usize, Error>;
    fn fail(&mut self);
    fn pop_event(&mut self) -> Option<Event>;
    fn pop_data(&mut self) -> Option<Vec<u8>>;
    fn send_data(&mut self, frame: &[u8], priority: u8) -> Result<(), Error>;
    /// The transport demultiplexes secondary firmware interfaces (ifidx
    /// 1..`vif_wire::MAX_IFS`): BCDC `flags2`/`BCDC_DCMD_IF_SHIFT` on SDIO,
    /// per-(ifidx, tid, da) flow rings and message ifidx on PCIe. Interface
    /// 0 behaviour of every method above is unchanged by it.
    const VIF_DEMUX: bool = false;
    /// This runtime is the `struct brcmf_if` view of a secondary bsscfg
    /// (`brcmfmac::vif_bsscfg::Bsscfg`). Role owners then issue the
    /// `brcmf_fil_bsscfg_*` form Linux uses where the primary keeps its
    /// established dcmd (e.g. `wsec` instead of `BRCMF_C_SET_WSEC`).
    const BSSCFG: bool = false;
    /// Retain `BRCMF_E_IF` and secondary-bsscfg events for
    /// [`Self::pop_vif_event`] (otherwise they are dropped, as Linux does
    /// for a bsscfg without `brcmf_if`). Disabling purges them.
    fn vif_listen(&mut self, _on: bool) {}
    /// Admit data on a secondary ifidx; only its interface owner calls
    /// this, after its own link lifecycle allows traffic.
    fn vif_open(&mut self, _ifidx: u8) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    /// Stop admitting data on `ifidx` and start retiring its native
    /// resources. `Ok(true)` only once none remain owned (PCIe flow delete
    /// completions); callers keep polling until then.
    fn vif_close(&mut self, _ifidx: u8) -> Result<bool, Error> {
        Err(Error::Unsupported)
    }
    fn pop_vif_event(&mut self) -> Option<Event> {
        None
    }
    fn pop_vif_data(&mut self, _ifidx: u8) -> Option<Vec<u8>> {
        None
    }
    fn send_vif_data(&mut self, _ifidx: u8, _frame: &[u8], _priority: u8) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    /// Control command addressed to firmware interface `ifidx`
    /// (`brcmf_fil_cmd_data` uses `ifp->ifidx`). Never carries AP scope.
    fn command_vif<'a>(
        &'a mut self,
        _ifidx: u8,
        _direction: Direction,
        _command: u32,
        _input: &'a [u8],
        _maximum: usize,
    ) -> impl Future<Output = Result<Vec<u8>, Error>> + Send + 'a {
        core::future::ready(Err(Error::Unsupported))
    }
    /// Record `need`'s firmware events and return the device-wide union
    /// every `event_msgs` writer must send (`brcmfmac::event_mask`; Linux
    /// `brcmf_fweh_activate_events` writes the union of all registered
    /// handlers). Transports without a composition return `events`.
    fn events_compose(
        &mut self,
        _need: crate::brcmfmac::event_mask::Need,
        events: crate::brcmfmac::event_mask::Mask,
    ) -> crate::brcmfmac::event_mask::Mask {
        events
    }
    /// A successful `event_msgs` SET carried `mask`.
    fn events_written(&mut self, _mask: crate::brcmfmac::event_mask::Mask) {}
    /// The mask last written, when the transport tracks it.
    fn events_current(&mut self) -> Option<crate::brcmfmac::event_mask::Mask> {
        None
    }
    /// Only a station's correlated link/key lifecycle calls this method.
    /// Transport completion alone must never call it or open a controlled port.
    fn set_link(&mut self, peer: Option<[u8; 6]>);
    /// Current negotiated 802.1D-to-AC rank map (`brcmf_get_assoc_ies`).
    /// Transports whose queueing does not consume it ignore the update.
    fn set_ac_priority(&mut self, _ac_priority: [u8; 8]) {}
    /// Interrupt wake source for the owner's service loop and whether a
    /// vector actually delivers it. `None` keeps the 1 ms polled service.
    fn wake_source(&self) -> Option<(alloc::sync::Arc<crate::brcmfmac::irq::Signal>, bool)> {
        None
    }
    /// System-suspend transport phase after the station link is down
    /// (Linux `dev_pm_ops.suspend`). Unsupported transports refuse it so
    /// the coordinator unwinds instead of losing firmware state.
    fn suspend_transport(&mut self) -> impl Future<Output = Result<(), Error>> + Send {
        async { Err(Error::Unsupported) }
    }
    /// Paired resume (Linux `dev_pm_ops.resume`). An error leaves this
    /// transport generation terminal.
    fn resume_transport(&mut self) -> impl Future<Output = Result<(), Error>> + Send {
        async { Err(Error::Unsupported) }
    }
    /// Linux `bus_if->wowl_supported`: the bus can keep the dongle powered
    /// and let it wake the host from system suspend (PCIe
    /// `pci_pme_capable(pdev, PCI_D3hot)`; SDIO `MMC_PM_KEEP_POWER` with a
    /// wake IRQ). Enabling PME / the platform wake source is the system-PM
    /// owner's job, not the driver's. Transports without one report false.
    fn wowl_supported(&mut self) -> bool {
        false
    }
    /// Linux `brcmf_bus_wowl_config`: WoWL was armed (`true`, end of
    /// `brcmf_configure_wowl`) or disarmed (`brcmf_cfg80211_resume`); the
    /// next [`Self::suspend_transport`] keeps a bus wake path. Buses whose
    /// suspend does not depend on it ignore it.
    fn wowl_config(&mut self, _enabled: bool) {}
    /// Bus-match firmware vendor (Linux `bus_if->fwvid`).
    fn firmware_vendor(&self) -> FirmwareVendor {
        FirmwareVendor::Wcc
    }
    /// Confirmed device stop for teardown or reset (Linux
    /// `brcmf_pcie_remove`/`brcmf_pcie_reset` before the ring release).
    /// `Ok` only when the transport proved its published DMA reclaimable;
    /// either way this generation accepts no further work. Transports
    /// without such a proof refuse it, which keeps teardown pinned.
    fn stop_transport(&mut self) -> impl Future<Output = Result<(), Error>> + Send {
        async { Err(Error::Unsupported) }
    }
    /// Drop the current transport generation now. Returns true only when
    /// its published memory was released after a complete stop proof;
    /// otherwise every mapping stays pinned (leaked by design).
    fn release_transport(&mut self) -> bool {
        false
    }
    /// After a successful [`Self::stop_transport`]: reset the device and
    /// boot a fresh firmware generation in place under the retained
    /// firmware authority (Linux `brcmf_pcie_reset`: release, reset,
    /// `brcmf_pcie_setup`). Transports without a device reset refuse it.
    fn reset_transport(&mut self) -> impl Future<Output = Result<(), Error>> + Send {
        async { Err(Error::Unsupported) }
    }
    /// Move the current (rebooted) generation and its retained authority
    /// into a new owner, leaving this one terminal and empty.
    fn take_generation(&mut self) -> Option<Self>
    where
        Self: Sized,
    {
        None
    }
    /// The transport generation is terminal (firmware halt, lost power,
    /// a fatal protocol or access error) and needs a reset to continue.
    fn transport_failed(&self) -> bool {
        false
    }
}
impl<T: PacketTransport> Fullmac for Runtime<T> {
    fn ap_enter(&mut self, original: crate::brcmfmac::ap_scope::Capture) -> Result<(), Error> {
        Runtime::ap_enter(self, original)
    }
    fn ap_send(
        &mut self,
        bytes: &[u8],
        priority: u8,
        original: &crate::brcmfmac::ap_scope::Capture,
    ) -> Result<crate::brcmfmac::ap_tx::Ticket, Error> {
        Runtime::ap_send(self, bytes, priority, original)
    }
    fn ap_leave(&mut self) -> Result<bool, Error> {
        Runtime::ap_leave(self)
    }
    fn ap_completed_prefix(&mut self) -> Result<bool, Error> {
        Runtime::ap_completed_prefix(self)
    }
    fn ap_quiet(&mut self) -> Result<bool, Error> {
        Runtime::ap_quiet(self)
    }
    fn ap_retire_peer(&mut self, peer: [u8; 6]) -> Result<bool, Error> {
        Runtime::ap_retire_peer(self, peer)
    }
    fn ap_source(&self) -> Option<crate::brcmfmac::ap_source::Source> {
        Runtime::ap_source(self)
    }
    async fn stop_transport(&mut self) -> Result<(), Error> {
        Runtime::stop_transport(self)
    }
    async fn suspend_transport(&mut self) -> Result<(), Error> {
        Runtime::suspend_transport(self).await
    }
    async fn resume_transport(&mut self) -> Result<(), Error> {
        Runtime::resume_transport(self).await
    }
    fn wowl_supported(&mut self) -> bool {
        Runtime::wowl_supported(self)
    }
    fn wowl_config(&mut self, enabled: bool) {
        Runtime::wowl_config(self, enabled)
    }
    fn release_transport(&mut self) -> bool {
        Runtime::release_transport(self)
    }
    fn transport_failed(&self) -> bool {
        Runtime::is_failed(self)
    }
    const FAMILY: Family = Family::Sdio;
    const EXTERNAL_CLM: bool = true;
    // The whole native SDIO AP composition (Card/F2/SDPCM/BCDC firmware-SME
    // path, Program ownership, stop/pin, preverification hold) is in place.
    // Metadata still requires an actual original typed Card/firmware source,
    // exact native `ap` capability token and GET_AP0 discovery; START then
    // requires its own actual command/BSS/SCB/key/port receipts.
    const PRIMARY_AP: bool = true;
    fn command<'a>(
        &'a mut self,
        direction: Direction,
        command: u32,
        input: &'a [u8],
        maximum: usize,
    ) -> impl Future<Output = Result<Vec<u8>, Error>> + Send + 'a {
        Runtime::command(self, direction, command, input, maximum)
    }
    fn command_ap<'a>(
        &'a mut self,
        original: &'a crate::brcmfmac::ap_scope::Capture,
        direction: Direction,
        command: u32,
        input: &'a [u8],
        maximum: usize,
    ) -> impl Future<Output = Result<Vec<u8>, Error>> + Send + 'a {
        Runtime::command_ap(self, original, direction, command, input, maximum)
    }
    async fn configure_bus(&mut self) -> Result<(), Error> {
        for name in [b"bus:txglom\0".as_slice(), b"bus:rxglom\0".as_slice()] {
            let mut bytes = name.to_vec();
            bytes.extend_from_slice(&0u32.to_le_bytes());
            self.command(Direction::Set, 263, &bytes, 1502).await?;
        }
        Ok(())
    }
    fn poll(&mut self) -> Result<usize, Error> {
        Runtime::poll(self)
    }
    fn fail(&mut self) {
        Runtime::fail(self)
    }
    fn pop_event(&mut self) -> Option<Event> {
        Runtime::pop_event(self)
    }
    fn pop_data(&mut self) -> Option<Vec<u8>> {
        Runtime::pop_data(self)
    }
    fn send_data(&mut self, frame: &[u8], priority: u8) -> Result<(), Error> {
        Runtime::send_data(self, frame, priority)
    }
    fn set_link(&mut self, _: Option<[u8; 6]>) {}
    const VIF_DEMUX: bool = true;
    fn vif_listen(&mut self, on: bool) {
        Runtime::vif_listen(self, on)
    }
    fn events_compose(
        &mut self,
        need: crate::brcmfmac::event_mask::Need,
        events: crate::brcmfmac::event_mask::Mask,
    ) -> crate::brcmfmac::event_mask::Mask {
        self.event_composition().compose(need, events)
    }
    fn events_written(&mut self, mask: crate::brcmfmac::event_mask::Mask) {
        self.event_composition().written(mask)
    }
    fn events_current(&mut self) -> Option<crate::brcmfmac::event_mask::Mask> {
        self.event_composition().current()
    }
    fn vif_open(&mut self, ifidx: u8) -> Result<(), Error> {
        Runtime::vif_open(self, ifidx)
    }
    fn vif_close(&mut self, ifidx: u8) -> Result<bool, Error> {
        Ok(Runtime::vif_close(self, ifidx))
    }
    fn pop_vif_event(&mut self) -> Option<Event> {
        Runtime::pop_vif_event(self)
    }
    fn pop_vif_data(&mut self, ifidx: u8) -> Option<Vec<u8>> {
        Runtime::pop_vif_data(self, ifidx)
    }
    fn send_vif_data(&mut self, ifidx: u8, frame: &[u8], priority: u8) -> Result<(), Error> {
        Runtime::send_data_on(self, ifidx, frame, priority)
    }
    const SECONDARY_AP: bool = true;
    fn ap_enter_on(
        &mut self,
        ifidx: u8,
        original: crate::brcmfmac::ap_scope::Capture,
    ) -> Result<(), Error> {
        Runtime::ap_enter_if(self, secondary(ifidx)?, original)
    }
    fn ap_send_on(
        &mut self,
        ifidx: u8,
        bytes: &[u8],
        priority: u8,
        original: &crate::brcmfmac::ap_scope::Capture,
    ) -> Result<crate::brcmfmac::ap_tx::Ticket, Error> {
        Runtime::ap_send_if(self, secondary(ifidx)?, bytes, priority, original)
    }
    fn ap_leave_on(&mut self, ifidx: u8) -> Result<bool, Error> {
        Runtime::ap_leave_if(self, secondary(ifidx)?)
    }
    fn ap_completed_prefix_on(&mut self, ifidx: u8) -> Result<bool, Error> {
        Runtime::ap_completed_prefix_if(self, secondary(ifidx)?)
    }
    fn ap_quiet_on(&mut self, ifidx: u8) -> Result<bool, Error> {
        Runtime::ap_completed_prefix_if(self, secondary(ifidx)?)
    }
    fn ap_retire_peer_on(&mut self, ifidx: u8, peer: [u8; 6]) -> Result<bool, Error> {
        Runtime::ap_retire_peer_if(self, secondary(ifidx)?, peer)
    }
    async fn command_ap_on<'a>(
        &'a mut self,
        ifidx: u8,
        original: &'a crate::brcmfmac::ap_scope::Capture,
        direction: Direction,
        command: u32,
        input: &'a [u8],
        maximum: usize,
    ) -> Result<Vec<u8>, Error> {
        Runtime::command_ap_if(
            self,
            secondary(ifidx)?,
            original,
            direction,
            command,
            input,
            maximum,
        )
        .await
    }
    fn command_vif<'a>(
        &'a mut self,
        ifidx: u8,
        direction: Direction,
        command: u32,
        input: &'a [u8],
        maximum: usize,
    ) -> impl Future<Output = Result<Vec<u8>, Error>> + Send + 'a {
        Runtime::command_on(self, ifidx, direction, command, input, maximum)
    }
    fn set_ac_priority(&mut self, ac_priority: [u8; 8]) {
        Runtime::set_ac_priority(self, ac_priority)
    }
    fn firmware_vendor(&self) -> FirmwareVendor {
        Runtime::firmware_vendor(self)
    }
    fn wake_source(&self) -> Option<(alloc::sync::Arc<crate::brcmfmac::irq::Signal>, bool)> {
        Runtime::interrupt(self).map(|signal| (signal, true))
    }
}

/// A secondary firmware interface index (1..`vif_wire::MAX_IFS`).
pub(crate) fn secondary(ifidx: u8) -> Result<u8, Error> {
    if ifidx == 0 || ifidx >= crate::brcmfmac::vif_wire::MAX_IFS {
        Err(Error::Malformed)
    } else {
        Ok(ifidx)
    }
}
