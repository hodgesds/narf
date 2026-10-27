// SPDX-License-Identifier: GPL-2.0-or-later
//! One retained native startup owner, shared by Device control and packet work.
//! Firmware/radio setup mutably borrows `Owner::io`; it never exports Native.
use super::{
    station::{self, Io},
    station_control::Admission,
};
use alloc::sync::Arc;
use narf_lib::mutex::Mutex;
pub(super) struct Owner<I: Io> {
    pub(super) io: I,
    station: Option<station::State>,
    active: bool,
}
impl<I: Io> Owner<I> {
    pub(super) async fn start_station(
        &mut self,
        environment: alloc::sync::Arc<dyn super::station::Environment>,
        admission: super::station_control::Admission,
    ) -> Result<super::station_control::Admission, super::station::Error> {
        if self.station.is_some() || self.active {
            return Err(super::station::Error::State);
        }
        self.io.station_allowed()?;
        let own = self.io.station_own()?;
        self.active = false; // State is retained before the first await
        self.station = Some(super::station::State::new(own, environment, admission));
        let station = self.station.as_mut().ok_or(super::station::Error::State)?;
        station.start(&mut self.io).await?;
        self.active = true;
        Ok(station.admission())
    }
    pub(super) fn station_local(&self) -> Option<[u8; 6]> {
        self.station.as_ref().map(super::station::State::local)
    }
    pub(super) fn station_peer(&self) -> Option<[u8; 6]> {
        self.station.as_ref().and_then(super::station::State::peer)
    }
    pub(super) fn station_ready(&self) -> bool {
        self.station
            .as_ref()
            .is_some_and(super::station::State::ready)
    }
    pub(super) fn station_check(&mut self) -> Result<(), super::station::Error> {
        let station = self.station.as_ref().ok_or(super::station::Error::State)?;
        if !self.active
            || matches!(
                station.phase(),
                super::station::Phase::Prepared
                    | super::station::Phase::Failed
                    | super::station::Phase::Stopped
            )
        {
            return Err(super::station::Error::State);
        }
        self.io
            .station_allowed()
            .map_err(super::station::Error::Native)
    }
    pub(super) fn station_phase(&self) -> Option<super::station::Phase> {
        self.station.as_ref().map(super::station::State::phase)
    }
    pub(super) fn station_candidates(
        &self,
    ) -> alloc::vec::Vec<narf_wireless::association::ObservedBss> {
        self.station
            .as_ref()
            .map_or_else(alloc::vec::Vec::new, super::station::State::candidates)
    }
    pub(super) fn station_information_elements(
        &self,
        peer: [u8; 6],
    ) -> Option<alloc::vec::Vec<u8>> {
        self.station.as_ref()?.information_elements(peer)
    }
    /// One worker pass: recognize interrupts (when armed), drain RPQ/RXQ
    /// through the station, then re-enable the mask (`rtw89_pci_napi_poll`).
    pub(super) fn station_poll(
        &mut self,
    ) -> Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, super::station::Error> {
        let station = self.station.as_mut().ok_or(super::station::Error::State)?;
        let events = self
            .io
            .irq_service()
            .map_err(super::station::Error::Native)?;
        if events.fatal() {
            return Err(super::station::Error::Halted);
        }
        let frames = station.poll(&mut self.io)?;
        self.io.irq_rearm().map_err(super::station::Error::Native)?;
        Ok(frames)
    }
    /// Arm interrupt delivery for the started station.
    pub(super) fn station_irq(
        &mut self,
        line: &Arc<super::irq::Line>,
    ) -> Result<u8, super::station::Error> {
        if !self.active || self.station.is_none() {
            return Err(super::station::Error::State);
        }
        self.io
            .irq_start(line)
            .map_err(super::station::Error::Native)
    }
    pub(super) fn station_send(&mut self, frame: &[u8]) -> Result<(), super::station::Error> {
        self.station
            .as_mut()
            .ok_or(super::station::Error::State)?
            .send(&mut self.io, frame)
    }
    pub(super) fn station_stop(&mut self) -> Result<(), super::station::Error> {
        match self.station.as_mut() {
            Some(station) => station.stop(&mut self.io),
            None => self
                .io
                .packet_stop()
                .map_err(super::station::Error::Transport),
        }
    }
    pub(super) async fn station_disconnect(&mut self) -> Result<(), super::station::Error> {
        self.station
            .as_mut()
            .ok_or(super::station::Error::State)?
            .disconnect(&mut self.io)
            .await
    }
    pub(super) async fn station_scan(
        &mut self,
        dwell_ms: u64,
    ) -> Result<alloc::vec::Vec<narf_wireless::association::ObservedBss>, super::station::Error>
    {
        self.station
            .as_mut()
            .ok_or(super::station::Error::State)?
            .scan_for(&mut self.io, dwell_ms)
            .await
    }
    pub(super) async fn station_associate(
        &mut self,
        bssid: [u8; 6],
        ssid: &[u8],
        pmk: Option<zeroize::Zeroizing<[u8; 32]>>,
        ies: &[u8],
    ) -> Result<(), super::station::Error> {
        self.station
            .as_mut()
            .ok_or(super::station::Error::State)?
            .associate(&mut self.io, bssid, ssid, pmk, ies)
            .await
    }
}
impl<I: Io> Drop for Owner<I> {
    fn drop(&mut self) {
        if let Some(station) = self.station.as_mut() {
            let _ = station.stop(&mut self.io);
        }
    }
}
pub(super) struct Lifecycle<I: Io> {
    pub(super) retained: Mutex<Option<Owner<I>>>,
}
impl<I: Io> Lifecycle<I> {
    /// Construct before the first firmware or packet DMA attempt. Production
    /// wraps the actual Startup, whose Firmware permanently retains Native.
    pub(super) fn new(io: I) -> Self {
        Self {
            retained: Mutex::new(Some(Owner {
                io,
                station: None,
                active: false,
            })),
        }
    }
    pub(super) async fn start_station(
        &self,
        environment: Arc<dyn station::Environment>,
        admission: Admission,
    ) -> Result<(), station::Error> {
        self.retained
            .lock()
            .await
            .as_mut()
            .ok_or(station::Error::State)?
            .start_station(environment, admission)
            .await
            .map(|_| ())
    }
}
