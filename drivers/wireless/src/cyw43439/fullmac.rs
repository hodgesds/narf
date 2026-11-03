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
    async fn stop_transport(&mut self) -> Result<(), Error> {
        Runtime::stop_transport(self)
    }
    fn release_transport(&mut self) -> bool {
        Runtime::release_transport(self)
    }
    fn transport_failed(&self) -> bool {
        Runtime::is_failed(self)
    }
    const FAMILY: Family = Family::Sdio;
    const EXTERNAL_CLM: bool = true;
    fn command<'a>(
        &'a mut self,
        direction: Direction,
        command: u32,
        input: &'a [u8],
        maximum: usize,
    ) -> impl Future<Output = Result<Vec<u8>, Error>> + Send + 'a {
        Runtime::command(self, direction, command, input, maximum)
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
