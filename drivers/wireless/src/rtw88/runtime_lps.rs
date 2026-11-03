// SPDX-License-Identifier: GPL-2.0-or-later
//! Explicit bounded nondeep LPS under the exact original retained station.
use crate::rtw88::{
    firmware_transport::{Error as NativeError, Io, Owner},
    runtime_ps_scope::{Bound, KIND},
    runtime_ps_wire::{self as wire, Pages, Profile},
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

async fn send(
    io: &mut impl Io,
    command: [u8; 8],
    source: &Bound,
    admission: &Admission,
) -> Result<(), NativeError> {
    for i in 0..=30 {
        if admission.run(|| source.invoke(|| io.mailbox_ready()))? {
            admission.run(|| source.invoke(|| io.mailbox_submit(command)))?;
            for j in 0..=30 {
                if admission.run(|| source.invoke(|| io.mailbox_consumed()))? {
                    return Ok(());
                }
                if j < 30 {
                    io.delay_us(100).await;
                }
            }
            return Err(NativeError::Timeout);
        }
        if i < 30 {
            io.delay_us(100).await;
        }
    }
    Err(NativeError::Timeout)
}

impl<I: Io> Owner<I> {
    pub(in crate::rtw88) fn lps_request(
        &mut self,
    ) -> Result<crate::rtw88::ContinuationRequest, NativeError> {
        self.io.station_continuation_request(&KIND)
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
        let (own, peer, aid) = station.lps_peer().ok_or(Error::Busy)?;
        if !self.io.station_ht_program_quiet()? {
            return Err(Error::Busy);
        }
        self.io.station_profile_readback()?;
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
        let mut attempt = Attempt {
            admission: admission.clone(),
            armed: true,
        };
        let boundary = self.mac.ok_or(Error::Busy)?.reserved_boundary;
        self.io
            .station_reserved_page(&pages.bytes, boundary, &source, &admission)
            .await?;
        send(&mut self.io, pages.locations, &source, &admission).await?;
        send(&mut self.io, wire::parameters(true), &source, &admission).await?;
        let mut sleeping = false;
        for i in 0..=100 {
            let tcr = admission.run(|| source.invoke(|| self.io.read32(wire::TCR)))?;
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
        send(&mut self.io, wire::parameters(false), &source, &admission).await?;
        let mut wake = false;
        let mut awake = false;
        for i in 0..=100 {
            let (idle, event) = station
                .lps_collect(&mut self.io, &source)
                .map_err(|_| Error::Generation)?;
            wake |= event;
            let tcr = admission.run(|| source.invoke(|| self.io.read32(wire::TCR)))?;
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
        admission.run(|| {
            source.invoke(|| {
                if station.peer() != Some(peer) {
                    return Err(NativeError::State);
                }
                self.io.station_profile_readback()?;
                self.io.station_allowed()
            })
        })?;
        attempt.armed = false;
        Ok(())
    }
}
