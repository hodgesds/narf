// SPDX-License-Identifier: GPL-2.0-or-later
//! Exclusive primary native monitor owner; no additional firmware bsscfg,
//! DATA/key/station/AP grant or injection follows a receive observation.
use super::{
    ap_scope::{Epoch, Policy},
    monitor_native::{self, Prepared},
    monitor_scope::{Capture, Received},
};
use crate::cyw43439::{fullmac::Fullmac, runtime::Error, station::Station};
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Prepared,
    Changing,
    Active,
    Stopping,
    Stopped,
}
pub(crate) struct Session {
    original: Capture,
    prepared: Option<Prepared>,
    reserved: bool,
    phase: Phase,
}
struct Operation {
    original: Capture,
    finished: bool,
}
impl Drop for Operation {
    fn drop(&mut self) {
        if !self.finished {
            self.original.retire();
        }
    }
}
impl Session {
    pub(crate) fn prepare<R: Fullmac>(
        station: &Station<R>,
        event: narf_net::iface::OpenStopEvent,
        channel: narf_wireless::monitor::Channel,
        policy: Policy,
        mode: Arc<AtomicU64>,
        generation: u64,
    ) -> Result<Self, Error> {
        let receiver = event.original_snapshot();
        if !R::PRIMARY_MONITOR
            || !event.up()
            || !event.current()
            || receiver.link_layer != narf_net::iface::LinkLayer::Ieee80211Radiotap
            || generation == 0
            || generation == u64::MAX
            || mode.load(Ordering::Acquire) != generation
        {
            return Err(Error::Authority);
        }
        let (frequency, chanspec) = station.monitor_channel(&policy, channel)?;
        let original = Capture {
            native: station.runtime.ap_source().ok_or(Error::Unsupported)?,
            event,
            policy,
            mode,
            generation,
            epoch: Epoch::new(),
            active: Arc::new(AtomicBool::new(false)),
            frequency,
            chanspec,
        };
        original.command_current()?;
        Ok(Self {
            original,
            prepared: None,
            reserved: false,
            phase: Phase::Prepared,
        })
    }
    pub(crate) fn original(&self) -> &Capture {
        &self.original
    }
    pub(crate) fn current(&self) -> Result<(), Error> {
        self.original.current()
    }
    pub(crate) fn active(&self) -> bool {
        self.phase == Phase::Active && self.current().is_ok()
    }
    pub(crate) fn retire(&self) {
        self.original.retire();
    }
    fn discard_prefix<R: Fullmac>(&self, runtime: &mut R) -> Result<bool, Error> {
        for _ in 0..4 {
            let count = runtime.poll()?;
            while runtime.pop_event().is_some() {}
            while runtime.pop_data().is_some() {}
            while runtime.pop_monitor().is_some() {}
            if count == 0 && runtime.ap_completed_prefix()? {
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub(crate) async fn start<R: Fullmac>(
        &mut self,
        station: &mut Station<R>,
    ) -> Result<(), Error> {
        if self.phase != Phase::Prepared || self.prepared.is_some() {
            return Err(Error::Busy);
        }
        self.original.command_current()?;
        let mut operation = Operation {
            original: self.original.clone(),
            finished: false,
        };
        let deadline = narf_time::Deadline::after_ms(2000);
        while !self.discard_prefix(&mut station.runtime)? {
            self.original.command_current()?;
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
        }
        self.prepared = Some(monitor_native::prepare(&mut station.runtime, &self.original).await?);
        let prepared = self.prepared.as_ref().unwrap();
        // This reserves matching raw DMA drain only. Before actual native
        // mode/channel readback, incoming raw payloads cannot be published.
        station.runtime.monitor_reserve(prepared.clone())?;
        self.reserved = true;
        self.phase = Phase::Changing;
        let armed = monitor_native::start(&mut station.runtime, prepared).await?;
        self.original.command_current()?;
        self.original.active.store(true, Ordering::Release);
        station.runtime.monitor_arm(armed)?;
        self.phase = Phase::Active;
        operation.finished = true;
        Ok(())
    }
    pub(crate) fn step<R: Fullmac>(
        &mut self,
        station: &mut Station<R>,
    ) -> Result<Vec<Received>, Error> {
        self.current()?;
        let mut received = Vec::new();
        for _ in 0..4 {
            station.runtime.poll()?;
            while let Some(event) = station.runtime.pop_event() {
                if event.header.if_idx != 0
                    || event.header.bsscfg_idx != 0
                    || matches!(event.header.event_type, 8 | 10 | 19 | 63)
                    || event.header.event_type == 16 && event.header.flags & 1 != 0
                {
                    self.retire();
                    return Err(Error::Malformed);
                }
            }
            while station.runtime.pop_data().is_some() {}
            while let Some(frame) = station.runtime.pop_monitor() {
                if received.len() == 32 {
                    continue;
                }
                received.push(frame);
            }
            if station.runtime.monitor_control_idle()? {
                self.current()?;
                return Ok(received);
            }
        }
        // A completed channel/loss event may still sit beyond this bounded
        // control budget. Continuous raw traffic need not become globally
        // idle, but no batch bypasses that actual pending control prefix.
        self.current()?;
        Ok(Vec::new())
    }
    pub(crate) async fn stop<R: Fullmac>(&mut self, station: &mut Station<R>) -> Result<(), Error> {
        self.retire();
        self.phase = Phase::Stopping;
        self.original
            .native
            .current()
            .map_err(|_| Error::Authority)?;
        if let Some(prepared) = self.prepared.as_ref() {
            monitor_native::stop(&mut station.runtime, prepared).await?;
        }
        let deadline = narf_time::Deadline::after_ms(2000);
        while !self.discard_prefix(&mut station.runtime)? {
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
        }
        if self.reserved {
            station.runtime.monitor_leave(&self.original)?;
            self.reserved = false;
        }
        self.phase = Phase::Stopped;
        Ok(())
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.retire();
    }
}
