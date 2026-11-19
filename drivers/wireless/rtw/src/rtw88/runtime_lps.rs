// SPDX-License-Identifier: GPL-2.0-or-later
//! Explicit bounded nondeep LPS under the exact original retained station.
use crate::rtw88::{
    firmware_transport::{Error as NativeError, Io, Owner, PsSubmit},
    runtime_ps_scope::{Bound, KIND},
    runtime_ps_wire::{self as wire, Pages, Profile},
    station::State,
    station_control::Admission,
};
use narf_bus::BusAddr;
use narf_net::{native_emission::Lifetime, Interface};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Busy,
    Generation,
    Native(NativeError),
}
impl From<NativeError> for Error {
    fn from(e: NativeError) -> Self {
        Self::Native(e)
    }
}
struct Attempt {
    admission: Admission,
    armed: bool,
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if self.armed {
            self.admission.close();
        }
    }
}
/// Describe the distinct complete nondeep LPS program for this retained
/// function. The returned metadata grants no sleep/RF or DMA authority.
pub async fn lps_request_function(
    address: BusAddr,
) -> Result<crate::rtw88::ContinuationRequest, Error> {
    let owner = crate::rtw88::functions::get(address).ok_or(Error::Generation)?;
    let interface = owner.interface.as_ref().ok_or(Error::Unsupported)?;
    let mut retained = interface.lifecycle.retained.lock().await;
    let owner = retained.as_mut().ok_or(Error::Busy)?;
    owner.lps_request().map_err(Error::Native)
}
/// Sleep the original associated fixed CCK1 station for1..100ms, then prove
/// firmware awake before ordinary DATA can resume. No low-clock/PG/WoW mode.
/// Cancellation or an ambiguous native transition closes the old station;
/// explicit confirmed reset/rejoin is required for its next generation.
pub async fn lps_function(address: BusAddr, milliseconds: u32) -> Result<(), Error> {
    if !(1..=100).contains(&milliseconds) {
        return Err(Error::Unsupported);
    }
    let function = crate::rtw88::functions::get(address).ok_or(Error::Generation)?;
    let _provision = function.provisioning.try_lock().ok_or(Error::Busy)?;
    let interface = function.interface.as_ref().ok_or(Error::Unsupported)?;
    let snapshot = narf_net::iface::lookup(interface.name()).ok_or(Error::Generation)?;
    if snapshot.mac != interface.mac() {
        return Err(Error::Generation);
    }
    let up = narf_net::iface::OpenStopEvent::observe(&snapshot)
        .filter(|e| e.up())
        .ok_or(Error::Generation)?;
    let host = up.native_identity().ok_or(Error::Generation)?;
    let mut retained = interface.lifecycle.retained.lock().await;
    if !up.current()
        || !crate::rtw88::functions::get(address)
            .is_some_and(|current| alloc::sync::Arc::ptr_eq(&current, &function))
    {
        return Err(Error::Generation);
    }
    retained
        .as_mut()
        .ok_or(Error::Busy)?
        .lps_window(host, milliseconds)
        .await
}

/// [`lps_request_function`] for the RTL8821CU claimed on USB `slot_id`.
pub async fn lps_request_usb(slot_id: u8) -> Result<crate::rtw88::ContinuationRequest, Error> {
    let station = crate::rtw88::usb_driver::station(slot_id).ok_or(Error::Generation)?;
    let mut retained = station.lifecycle.retained.lock().await;
    let owner = retained.as_mut().ok_or(Error::Busy)?;
    owner.lps_request().map_err(Error::Native)
}
/// [`lps_function`] for the RTL8821CU claimed on USB `slot_id`: the same
/// bounded nondeep LPS window over the USB backend (station TXBUF upload on
/// the bulk BEACON queue, PS H2C through EP0 HMEBOX). The claimed function
/// and the UP interface must stay the same across the whole window.
pub async fn lps_usb(slot_id: u8, milliseconds: u32) -> Result<(), Error> {
    if !(1..=100).contains(&milliseconds) {
        return Err(Error::Unsupported);
    }
    let station = crate::rtw88::usb_driver::station(slot_id).ok_or(Error::Generation)?;
    let snapshot = narf_net::iface::lookup(station.name()).ok_or(Error::Generation)?;
    if snapshot.mac != station.mac() {
        return Err(Error::Generation);
    }
    let up = narf_net::iface::OpenStopEvent::observe(&snapshot)
        .filter(|e| e.up())
        .ok_or(Error::Generation)?;
    let host = up.native_identity().ok_or(Error::Generation)?;
    let mut retained = station.lifecycle.retained.lock().await;
    if !up.current()
        || !crate::rtw88::usb_driver::station(slot_id)
            .is_some_and(|current| alloc::sync::Arc::ptr_eq(&current, &station))
    {
        return Err(Error::Generation);
    }
    retained
        .as_mut()
        .ok_or(Error::Busy)?
        .lps_window(host, milliseconds)
        .await
}

type Peer = ([u8; 6], [u8; 6], u16);

/// One PS H2C under the exact original source, Linux fw.c
/// rtw_fw_send_h2c_command. Native RX/TX/command progress after HMEBOX_EXT
/// staging leaves the command unissued: that prefix is retired privately
/// through `lps_collect` (peer loss/key/control still denies) and the
/// command is staged again. `expect` (pre-entry only) requires the original
/// LPS peer to stay idle and unchanged, else `Busy` with nothing issued.
/// A published low word is never resent; only its consumption is polled.
async fn send<I: Io>(
    io: &mut I,
    station: &mut State,
    command: [u8; 8],
    source: &Bound,
    admission: &Admission,
    expect: Option<Peer>,
) -> Result<(), Error> {
    for i in 0..=30 {
        if crate::rtw88::firmware_transport::enclosed(
            |op| admission.run(|| source.invoke(op)),
            io.mailbox_ready(),
        )
        .await?
        {
            let mut scope = |op: &mut dyn FnMut() -> Result<bool, NativeError>| {
                admission.run(|| source.invoke(op))
            };
            match io.ps_mailbox_submit(command, &mut scope).await? {
                PsSubmit::Issued => {
                    for j in 0..=30 {
                        if crate::rtw88::firmware_transport::enclosed(
                            |op| admission.run(|| source.invoke(op)),
                            io.mailbox_consumed(),
                        )
                        .await?
                        {
                            return Ok(());
                        }
                        if j < 30 {
                            io.delay_us(100).await;
                        }
                    }
                    return Err(NativeError::Timeout.into());
                }
                PsSubmit::Unissued => {
                    station
                        .lps_collect(io, source)
                        .map_err(|_| Error::Generation)?;
                    if expect.is_some() && station.lps_peer() != expect {
                        return Err(Error::Busy);
                    }
                }
            }
        }
        if i < 30 {
            io.delay_us(100).await;
        }
    }
    Err(NativeError::Timeout.into())
}

impl<I: Io> Owner<I> {
    pub(in crate::rtw88) fn lps_request(
        &mut self,
    ) -> Result<crate::rtw88::ContinuationRequest, NativeError> {
        self.io.station_continuation_request(&KIND)
    }
    /// The interface advertises power save (`SUPPORTS_PS`) only when this
    /// retained firmware has a nondeep LPS profile and the separately
    /// signed N2xZ continuation loads over the current station gate.
    pub(in crate::rtw88) fn lps_capable(&mut self) -> bool {
        self.info
            .and_then(|info| Profile::from_firmware(self.did, info))
            .is_some()
            && matches!(self.io.station_continuation(&KIND), Ok(Some(_)))
    }
    pub(in crate::rtw88) async fn lps_window(
        &mut self,
        host: Lifetime,
        ms: u32,
    ) -> Result<(), Error> {
        if !(1..=100).contains(&ms) {
            return Err(Error::Unsupported);
        }
        self.station_check().map_err(|_| Error::Busy)?;
        let station = self.station.as_mut().ok_or(Error::Busy)?;
        // ps.c `rtw_enter_lps`: coexistence `wl_force_lps_ctrl` refuses LPS.
        if station.coex_forces_lps_off() {
            return Err(Error::Busy);
        }
        let (own, peer, aid) = station.lps_peer().ok_or(Error::Busy)?;
        if !self.io.station_ht_program_quiet().await? {
            return Err(Error::Busy);
        }
        self.io.station_profile_readback().await?;
        let info = self.info.ok_or(Error::Busy)?;
        let profile = Profile::from_firmware(self.did, info).ok_or(Error::Unsupported)?;
        let pages = Pages::station(own, peer, aid, false).ok_or(Error::Busy)?;
        let grant = self
            .io
            .station_continuation(&KIND)?
            .ok_or(Error::Unsupported)?;
        let gate = self.io.station_gate()?;
        let admission = station.admission();
        let source = Bound::new(
            grant,
            gate,
            self.io.station_publication()?.with_epoch(admission.epoch()),
            admission.epoch(),
            host,
        )?;
        // Consume/discard old RFON before issuing a new sleep/wake command.
        let (idle, _) = match station.lps_collect(&mut self.io, &source) {
            Ok(result) => result,
            Err(_) => {
                admission.close();
                return Err(Error::Generation);
            }
        };
        if !idle || station.lps_peer() != Some((own, peer, aid)) {
            return Err(Error::Busy);
        }
        let boundary = self.mac.ok_or(Error::Busy)?.reserved_boundary;
        let mut attempt = Attempt {
            admission: admission.clone(),
            armed: true,
        };
        self.io
            .station_reserved_page(&pages.bytes, boundary, &source, &admission)
            .await?;
        let expect = Some((own, peer, aid));
        // ps.c `rtw_enter_lps_core`: `rtw_coex_lps_notify(COEX_LPS_ENABLE)`
        // before `rtw_fw_set_pwr_mode`.
        station
            .coex_lps(&mut self.io, true)
            .await
            .map_err(|_| Error::Generation)?;
        for command in [pages.locations, wire::parameters(true)] {
            match send(&mut self.io, station, command, &source, &admission, expect).await {
                // Unissued before LPS entry: firmware stays active, the page
                // was restored and collected RX stays queued for ordinary
                // processing, so the original station remains open.
                // Coexistence returns to the awake state with it.
                Err(Error::Busy) => {
                    station
                        .coex_lps(&mut self.io, false)
                        .await
                        .map_err(|_| Error::Generation)?;
                    attempt.armed = false;
                    return Err(Error::Busy);
                }
                result => result?,
            }
        }
        let mut sleeping = false;
        for i in 0..=100 {
            let tcr = crate::rtw88::firmware_transport::enclosed(
                |op| admission.run(|| source.invoke(op)),
                self.io.read32(wire::TCR),
            )
            .await?;
            if tcr == u32::MAX {
                return Err(NativeError::Gone.into());
            }
            if tcr & 0x80 != 0 {
                sleeping = true;
                break;
            }
            if i < 100 {
                self.io.delay_us(1000).await;
            }
        }
        if !sleeping {
            return Err(NativeError::Timeout.into());
        }
        self.io.delay_us(u64::from(ms) * 1000).await;
        // Retire the complete pre-wake native prefix. Old RFON is deliberately
        // ignored; DATA/GTK/EAPOL stays private until actual awake completion.
        let mut idle = false;
        for _ in 0..16 {
            let (ready, _) = station
                .lps_collect(&mut self.io, &source)
                .map_err(|_| Error::Generation)?;
            if ready {
                idle = true;
                break;
            }
            self.io.delay_us(1000).await;
        }
        if !idle {
            return Err(NativeError::Timeout.into());
        }
        send(
            &mut self.io,
            station,
            wire::parameters(false),
            &source,
            &admission,
            None,
        )
        .await?;
        let mut wake = false;
        let mut awake = false;
        for i in 0..=100 {
            let (idle, event) = station
                .lps_collect(&mut self.io, &source)
                .map_err(|_| Error::Generation)?;
            wake |= event;
            let tcr = crate::rtw88::firmware_transport::enclosed(
                |op| admission.run(|| source.invoke(op)),
                self.io.read32(wire::TCR),
            )
            .await?;
            if idle && wire::register_awake(tcr) && (!profile.c2h_wake || wake) {
                awake = true;
                break;
            }
            if tcr == u32::MAX {
                return Err(NativeError::Gone.into());
            }
            if i < 100 {
                self.io.delay_us(1000).await;
            }
        }
        if !awake {
            return Err(NativeError::Timeout.into());
        }
        // ps.c `rtw_leave_lps_core`: `rtw_coex_lps_notify(COEX_LPS_DISABLE)`
        // after the ACTIVE `rtw_fw_set_pwr_mode` and leave check.
        station
            .coex_lps(&mut self.io, false)
            .await
            .map_err(|_| Error::Generation)?;
        crate::rtw88::firmware_transport::enclosed(
            |op| admission.run(|| source.invoke(op)),
            async {
                if station.peer() != Some(peer) {
                    return Err(NativeError::State);
                }
                self.io.station_profile_readback().await?;
                self.io.station_allowed()
            },
        )
        .await?;
        attempt.armed = false;
        Ok(())
    }
}
