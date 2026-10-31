// SPDX-License-Identifier: GPL-2.0-or-later
//! Qualified legacy20 channel changes use verified retirement and a fresh
//! physical generation. No old key, packet ring or cached BSS migrates.
use super::*;
impl<I, M, E> Device<I, M, E>
where
    I: Port<Buffer = M> + 'static,
    M: Memory + 'static,
    E: recovery::Rebuild<I, M> + 'static,
{
    pub(super) async fn retune_once(&self, channel: u8) -> Result<bool, Error> {
        let _control = self.lifecycle.control.lock().await;
        if !(1..=11).contains(&channel)
            || self.removed.load(Ordering::Acquire)
            || self.lifecycle.suspended.load(Ordering::Acquire)
        {
            return Err(Error::State);
        }
        // Pure source/policy admission precedes closing or any native write;
        // actual rebuild and every publication check current grants again.
        self.environment.allow_channel(&self.factory, channel)?;
        if channel == self.lifecycle.channel.load(Ordering::Acquire)
            && !self.admission.closed.load(Ordering::Acquire)
        {
            return Ok(false);
        }
        {
            let storage = self.prepared.lock().await;
            if !self.admission.closed.load(Ordering::Acquire)
                && storage.as_ref().is_some_and(|owner| {
                    !matches!(
                        owner.station_phase(),
                        station::Phase::Dormant | station::Phase::Passive
                    )
                })
            {
                return Err(Error::Busy);
            }
        }
        self.request_abort();
        self.lifecycle.channel.store(channel, Ordering::Release);
        self.recover_locked().await
    }
}

/// A single-channel scan can select a noninitial qualified channel. Multi-
/// channel dwell aggregation is a separate public scan continuation.
pub(super) fn scan_channel(request: &ScanRequest, current: u8) -> Result<u8, WirelessError> {
    let mut selected = None;
    for &frequency in &request.frequencies_mhz {
        if !(2412..=2462).contains(&frequency) || (frequency - 2407) % 5 != 0 {
            return Err(WirelessError::NotSupported);
        }
        let channel = ((frequency - 2407) / 5) as u8;
        if selected
            .replace(channel)
            .is_some_and(|previous| previous != channel)
        {
            return Err(WirelessError::NotSupported);
        }
    }
    for &raw in &request.channels {
        let channel = u8::try_from(raw).map_err(|_| WirelessError::NotSupported)?;
        if !(1..=11).contains(&channel) {
            return Err(WirelessError::NotSupported);
        }
        if selected
            .replace(channel)
            .is_some_and(|previous| previous != channel)
        {
            return Err(WirelessError::NotSupported);
        }
    }
    Ok(selected.unwrap_or(current))
}
