// SPDX-License-Identifier: GPL-2.0-or-later
//! Per-bsscfg [`Fullmac`] adapter for one secondary firmware interface.
//!
//! Linux addresses every firmware operation of an additional interface
//! through its own `struct brcmf_if` (`ifp->ifidx`, `ifp->bsscfgidx`):
//! `fwil.c` `brcmf_fil_cmd_*`/`brcmf_fil_iovar_*` go to `ifp->ifidx`, and
//! `brcmf_fil_bsscfg_*` additionally wrap the iovar with
//! `brcmf_create_bsscfg` (`bsscfg:` + name + le32 `bsscfgidx`). Events reach
//! the interface through `fweh.c::brcmf_fweh_event_worker`
//! (`iflist[emsg.bsscfgidx]`) and data through `brcmf_get_ifp(ifidx)`.
//!
//! [`Bsscfg`] is that `brcmf_if` view over the primary transport: it borrows
//! the primary runtime, the transport generation's
//! [`vif_owner::Owner`](super::vif_owner::Owner) and the persistent
//! [`Link`] record of one live registry [`Entry`]. Interface-0 methods of
//! the runtime are never reached through it: commands use
//! [`Fullmac::command_vif`], events [`Owner::pop_event`], data
//! [`Fullmac::pop_vif_data`]/[`Fullmac::send_vif_data`]. It grants no AP
//! Program, monitor, PM or transport-lifecycle authority (all refused), and
//! it fails closed (bsscfg-local) once its entry left the registry.
//!
//! A role owner (`Station`) owns its runtime by value, so a persistent
//! secondary role is held over [`Parked`] and rebound to a fresh
//! [`Bsscfg`] for each operation (`station::vif`).
use super::{
    vif_owner::Owner,
    vif_wire::{self, Entry},
};
use crate::cyw43439::{
    fullmac::{Family, FirmwareVendor, Fullmac},
    ioctl::Direction,
    runtime::{Error, Event},
};
use alloc::vec::Vec;
use core::{future::Future, marker::PhantomData};

/// `BRCMF_C_GET_VAR` / `BRCMF_C_SET_VAR`.
const GET_VAR: u32 = 262;
const SET_VAR: u32 = 263;

/// Iovars Linux issues through `brcmf_fil_bsscfg_{int,data}_{set,get}`
/// (`cfg80211.c`, `p2p.c`, `feature.c`, 7.3-rc4). Every other iovar is an
/// ordinary `brcmf_fil_iovar_*` addressed only by `ifp->ifidx`.
pub const BSSCFG_IOVARS: [&[u8]; 15] = [
    b"actframe",
    b"actframe_abort",
    b"auth",
    b"bip",
    b"interface_remove",
    b"join",
    b"mfp",
    b"p2p_scan",
    b"p2p_state",
    b"ssid",
    b"vndr_ie",
    b"wme_bss_disable",
    b"wpa_auth",
    b"wsec",
    b"wsec_key",
];

/// The `brcmf_fil_*` wire form of `input` for secondary bsscfg `bsscfgidx`:
/// a `BSSCFG_IOVARS` GET/SET_VAR gains the `bsscfg:` prefix; anything else
/// (plain iovars, direct dcmds) is unchanged. `None` means unchanged.
pub fn wire_command(bsscfgidx: u8, command: u32, input: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    if command != GET_VAR && command != SET_VAR {
        return Ok(None);
    }
    let end = input
        .iter()
        .position(|&byte| byte == 0)
        .ok_or(Error::Malformed)?;
    let (name, data) = (&input[..end], &input[end + 1..]);
    if !BSSCFG_IOVARS.contains(&name) {
        return Ok(None);
    }
    vif_wire::bsscfg_iovar(bsscfgidx, name, data).map(Some)
}

/// Persistent per-bsscfg adapter state (one live registry entry).
#[derive(Debug)]
pub struct Link {
    entry: Entry,
    failed: bool,
    peer: Option<[u8; 6]>,
}

impl Link {
    pub fn new(entry: Entry) -> Self {
        Self {
            entry,
            failed: false,
            peer: None,
        }
    }
    pub fn entry(&self) -> Entry {
        self.entry
    }
    /// The role owner's correlated link (`Fullmac::set_link`): the peer
    /// whose controlled port is open, or `None`.
    pub fn peer(&self) -> Option<[u8; 6]> {
        self.peer
    }
    /// Bsscfg-local fail-stop (role protocol violation or a lost entry).
    pub fn failed(&self) -> bool {
        self.failed
    }
}

/// `struct brcmf_if` view of one secondary bsscfg over the primary runtime.
pub struct Bsscfg<'a, R: Fullmac> {
    runtime: &'a mut R,
    owner: &'a mut Owner,
    link: &'a mut Link,
}

impl<R: Fullmac> core::fmt::Debug for Bsscfg<'_, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Bsscfg")
            .field("link", &self.link)
            .finish_non_exhaustive()
    }
}

impl<'a, R: Fullmac> Bsscfg<'a, R> {
    pub fn new(runtime: &'a mut R, owner: &'a mut Owner, link: &'a mut Link) -> Self {
        Self {
            runtime,
            owner,
            link,
        }
    }
    /// The entry is still this generation's live registry record.
    fn live(&self) -> bool {
        self.owner
            .registry()
            .by_bsscfgidx(self.link.entry.bsscfgidx)
            == Some(self.link.entry)
    }
    fn usable(&mut self) -> Result<(), Error> {
        if !self.link.failed && !self.live() {
            // fweh brcmf_remove_interface: the bsscfg is gone.
            self.link.failed = true;
            self.link.peer = None;
        }
        if self.link.failed || self.runtime.transport_failed() {
            Err(Error::Failed)
        } else {
            Ok(())
        }
    }
    async fn command_inner(
        &mut self,
        direction: Direction,
        command: u32,
        input: &[u8],
        maximum: usize,
    ) -> Result<Vec<u8>, Error> {
        self.usable()?;
        let entry = self.link.entry;
        match wire_command(entry.bsscfgidx, command, input)? {
            Some(wrapped) => {
                self.runtime
                    .command_vif(entry.ifidx, direction, command, &wrapped, maximum)
                    .await
            }
            None => {
                self.runtime
                    .command_vif(entry.ifidx, direction, command, input, maximum)
                    .await
            }
        }
    }
}

impl<R: Fullmac> Bsscfg<'_, R> {
    /// AP Program dcmd on this bsscfg: the same `brcmf_fil_*` form as
    /// [`Self::command_inner`], under the transport's per-ifidx AP owner.
    async fn command_ap_inner(
        &mut self,
        original: &super::ap_scope::Capture,
        direction: Direction,
        command: u32,
        input: &[u8],
        maximum: usize,
    ) -> Result<Vec<u8>, Error> {
        self.usable()?;
        let entry = self.link.entry;
        // Do not program past a retained native denial of this bsscfg.
        if direction == Direction::Set
            && self
                .owner
                .events_for(&entry)
                .any(|event| original.program_event_blocks(&event.header))
        {
            return Err(Error::Busy);
        }
        match wire_command(entry.bsscfgidx, command, input)? {
            Some(wrapped) => {
                self.runtime
                    .command_ap_on(entry.ifidx, original, direction, command, &wrapped, maximum)
                    .await
            }
            None => {
                self.runtime
                    .command_ap_on(entry.ifidx, original, direction, command, input, maximum)
                    .await
            }
        }
    }
}

impl<R: Fullmac> Fullmac for Bsscfg<'_, R> {
    const FAMILY: Family = R::FAMILY;
    const EXTERNAL_CLM: bool = R::EXTERNAL_CLM;
    const BAND_5GHZ: bool = R::BAND_5GHZ;
    const VHT80: bool = R::VHT80;
    const BSSCFG: bool = true;
    // PRIMARY_AP / PRIMARY_MONITOR / VIF_DEMUX stay false: those owners are
    // interface-0 (or interface-owner) authorities, never per bsscfg.
    /// This bsscfg may own a firmware-SME AP on its own ifidx
    /// (`brcmf_cfg80211_start_ap` on `ifp`), through the transport's
    /// per-ifidx AP owner.
    const SECONDARY_AP: bool = R::SECONDARY_AP;

    /// This bsscfg's role owner is its own `Need::Secondary(ifidx)`; the
    /// union stays the transport's device-wide one.
    fn events_compose(
        &mut self,
        need: super::event_mask::Need,
        events: super::event_mask::Mask,
    ) -> super::event_mask::Mask {
        let need = match need {
            super::event_mask::Need::Primary => {
                super::event_mask::Need::Secondary(self.link.entry.ifidx)
            }
            other => other,
        };
        self.runtime.events_compose(need, events)
    }
    fn events_written(&mut self, mask: super::event_mask::Mask) {
        self.runtime.events_written(mask)
    }
    fn events_current(&mut self) -> Option<super::event_mask::Mask> {
        self.runtime.events_current()
    }
    fn ap_source(&self) -> Option<super::ap_source::Source> {
        if self.link.failed {
            return None;
        }
        self.runtime.ap_source()
    }
    fn ap_enter(&mut self, original: super::ap_scope::Capture) -> Result<(), Error> {
        self.usable()?;
        if self.owner.events_for(&self.link.entry).next().is_some() {
            return Err(Error::Busy);
        }
        self.runtime.ap_enter_on(self.link.entry.ifidx, original)
    }
    fn ap_send(
        &mut self,
        bytes: &[u8],
        priority: u8,
        original: &super::ap_scope::Capture,
    ) -> Result<super::ap_tx::Ticket, Error> {
        self.usable()?;
        // A retained record of this bsscfg reaches its AP owner first.
        if self.owner.events_for(&self.link.entry).next().is_some() {
            return Err(Error::Busy);
        }
        self.runtime
            .ap_send_on(self.link.entry.ifidx, bytes, priority, original)
    }
    // Retirement never requires a live entry: after an IF DEL the AP
    // owner still retires its own ifidx's flows and TX terminals.
    fn ap_leave(&mut self) -> Result<bool, Error> {
        self.runtime.ap_leave_on(self.link.entry.ifidx)
    }
    fn ap_completed_prefix(&mut self) -> Result<bool, Error> {
        if self.owner.events_for(&self.link.entry).next().is_some() {
            return Ok(false);
        }
        self.runtime.ap_completed_prefix_on(self.link.entry.ifidx)
    }
    fn ap_quiet(&mut self) -> Result<bool, Error> {
        if self.owner.events_for(&self.link.entry).next().is_some() {
            return Ok(false);
        }
        self.runtime.ap_quiet_on(self.link.entry.ifidx)
    }
    fn ap_retire_peer(&mut self, peer: [u8; 6]) -> Result<bool, Error> {
        self.runtime.ap_retire_peer_on(self.link.entry.ifidx, peer)
    }
    fn command_ap<'b>(
        &'b mut self,
        original: &'b super::ap_scope::Capture,
        direction: Direction,
        command: u32,
        input: &'b [u8],
        maximum: usize,
    ) -> impl Future<Output = Result<Vec<u8>, Error>> + Send + 'b {
        self.command_ap_inner(original, direction, command, input, maximum)
    }

    fn command<'b>(
        &'b mut self,
        direction: Direction,
        command: u32,
        input: &'b [u8],
        maximum: usize,
    ) -> impl Future<Output = Result<Vec<u8>, Error>> + Send + 'b {
        self.command_inner(direction, command, input, maximum)
    }
    async fn configure_bus(&mut self) -> Result<(), Error> {
        // Bus aggregation is per device, configured by the primary.
        self.usable()
    }
    /// The shared transport poll, then the `fweh` secondary event worker so
    /// this bsscfg's events reach [`Self::pop_event`].
    fn poll(&mut self) -> Result<usize, Error> {
        self.usable()?;
        let consumed = self.runtime.poll()?;
        if self.owner.service(self.runtime).is_err() {
            // Bounded secondary queue overflow: the transport fail-stops
            // exactly as the primary worker does.
            self.runtime.fail();
            return Err(Error::Failed);
        }
        self.usable()?;
        Ok(consumed)
    }
    /// Fail-stop this bsscfg only; the primary interface keeps running.
    fn fail(&mut self) {
        self.link.failed = true;
        self.link.peer = None;
    }
    fn pop_event(&mut self) -> Option<Event> {
        if self.link.failed {
            return None;
        }
        let entry = self.link.entry;
        self.owner.pop_event(&entry)
    }
    fn pop_data(&mut self) -> Option<Vec<u8>> {
        if self.link.failed {
            return None;
        }
        self.runtime.pop_vif_data(self.link.entry.ifidx)
    }
    fn send_data(&mut self, frame: &[u8], priority: u8) -> Result<(), Error> {
        self.usable()?;
        self.runtime
            .send_vif_data(self.link.entry.ifidx, frame, priority)
    }
    fn set_link(&mut self, peer: Option<[u8; 6]>) {
        self.link.peer = if self.link.failed { None } else { peer };
    }
    fn wake_source(&self) -> Option<(alloc::sync::Arc<super::irq::Signal>, bool)> {
        self.runtime.wake_source()
    }
    fn firmware_vendor(&self) -> FirmwareVendor {
        self.runtime.firmware_vendor()
    }
    fn transport_failed(&self) -> bool {
        self.link.failed || self.runtime.transport_failed()
    }
    fn wide_phy(&self) -> bool {
        self.runtime.wide_phy()
    }
}

/// Inert runtime a persistent secondary role is held over between
/// operations. Every method refuses; constants mirror `R` so the parked
/// role keeps the same type-level profile.
pub struct Parked<R>(PhantomData<fn() -> R>);

impl<R> Parked<R> {
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<R> core::fmt::Debug for Parked<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Parked")
    }
}

impl<R> Default for Parked<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: Fullmac> Fullmac for Parked<R> {
    const FAMILY: Family = R::FAMILY;
    const EXTERNAL_CLM: bool = R::EXTERNAL_CLM;
    const BAND_5GHZ: bool = R::BAND_5GHZ;
    const VHT80: bool = R::VHT80;
    fn command<'b>(
        &'b mut self,
        _: Direction,
        _: u32,
        _: &'b [u8],
        _: usize,
    ) -> impl Future<Output = Result<Vec<u8>, Error>> + Send + 'b {
        core::future::ready(Err(Error::Failed))
    }
    async fn configure_bus(&mut self) -> Result<(), Error> {
        Err(Error::Failed)
    }
    fn poll(&mut self) -> Result<usize, Error> {
        Err(Error::Failed)
    }
    fn fail(&mut self) {}
    fn pop_event(&mut self) -> Option<Event> {
        None
    }
    fn pop_data(&mut self) -> Option<Vec<u8>> {
        None
    }
    fn send_data(&mut self, _: &[u8], _: u8) -> Result<(), Error> {
        Err(Error::Failed)
    }
    fn set_link(&mut self, _: Option<[u8; 6]>) {}
}
