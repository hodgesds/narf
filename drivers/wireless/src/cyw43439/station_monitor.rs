// SPDX-License-Identifier: GPL-2.0-or-later
//! Monitor RX still requires the exact native inventory and every original
//! overlapping signed rule. It does not acquire station transmit permission.
use super::*;
use crate::brcmfmac::ap_scope::Policy;
impl<R: Fullmac> Station<R> {
    pub(crate) fn monitor_channel(
        &self,
        policy: &Policy,
        request: narf_wireless::monitor::Channel,
    ) -> Result<(u16, u16), Error> {
        if !R::PRIMARY_MONITOR
            || self.ap_station_busy()
            || !policy.current()
            || !Arc::ptr_eq(policy.domain(), &self.domain)
            || !matches!(request.width, 0 | 1)
            || request.center1_mhz != request.frequency_mhz
            || request.center2_mhz != 0
        {
            return Err(Error::Unsupported);
        }
        let primary = channel::from_frequency(request.frequency_mhz).ok_or(Error::Unsupported)?;
        if !self.channels.contains(&primary)
            || primary > 14 && !R::BAND_5GHZ
            || channel_ceiling(&self.domain, primary, false).is_none()
        {
            return Err(Error::Authority);
        }
        Ok((
            u16::try_from(request.frequency_mhz).map_err(|_| Error::Unsupported)?,
            channel::encode20(primary).ok_or(Error::Unsupported)?,
        ))
    }
}
