// SPDX-License-Identifier: GPL-2.0-or-later
//! Live host-policy observation, separate from firmware/RF quiescence.
use super::{channel_ceiling, channel_power, Fullmac, Station};
use crate::cyw43439::runtime::Error;
use alloc::{sync::Arc, vec::Vec};
use core::{
    future::{poll_fn, Future},
    task::Poll,
};
use narf_wireless::reg::{db::Database, RegulatoryDomain};

/// A trusted policy installer supplies an immutable current snapshot or
/// absence. This seam does not authenticate arbitrary caller-created domains.
pub trait PolicySource: Send + Sync {
    fn snapshot(&self) -> Option<Arc<RegulatoryDomain>>;
}
impl PolicySource for Database {
    fn snapshot(&self) -> Option<Arc<RegulatoryDomain>> {
        Database::snapshot(self)
    }
}
#[derive(Debug)]
pub struct GlobalPolicy;
impl PolicySource for GlobalPolicy {
    fn snapshot(&self) -> Option<Arc<RegulatoryDomain>> {
        narf_wireless::reg::db::snapshot()
    }
}

#[derive(Clone, Copy)]
pub(super) struct TxGrant {
    channel: u8,
    power: u8,
    country: [u8; 2],
}

impl<R: Fullmac> Station<R> {
    /// Live policy for native attachment or an explicitly owned platform DB.
    /// The fixed-domain initialize API retains its snapshot-only contract.
    pub async fn initialize_live(
        runtime: R,
        clm: &[u8],
        source: Arc<dyn PolicySource>,
    ) -> Result<Self, Error> {
        let domain = source.snapshot().ok_or(Error::Authority)?;
        let mut station = Self::initialize_inner(runtime, clm, domain, Some(source)).await?;
        station.refresh_policy()?;
        let domain = station.domain.clone();
        station
            .channels
            .retain(|&ch| channel_ceiling(&domain, ch, false).is_some());
        if station.channels.is_empty() {
            return Err(station.deny_policy());
        }
        Ok(station)
    }

    pub(super) fn deny_policy(&mut self) -> Error {
        self.runtime.fail();
        self.runtime.set_link(None);
        self.bssid = None;
        self.connection = None;
        self.cache.clear();
        Error::Authority
    }

    pub(super) fn refresh_policy(&mut self) -> Result<bool, Error> {
        let Some(source) = &self.policy else {
            return Ok(false);
        };
        let Some(domain) = source.snapshot() else {
            return Err(self.deny_policy());
        };
        if Arc::ptr_eq(&domain, &self.domain) {
            return Ok(false);
        }
        // Firmware country/CLM was configured during this exact lifecycle.
        // A different country requires an independently owned reset/reload.
        if domain.country_code != self.domain.country_code {
            return Err(self.deny_policy());
        }
        self.domain = domain;
        Ok(true)
    }

    pub(super) fn check_receive_policy(&mut self, channels: &[u8]) -> Result<(), Error> {
        self.refresh_policy()?;
        if channels
            .iter()
            .any(|&ch| channel_ceiling(&self.domain, ch, false).is_none())
        {
            return Err(self.deny_policy());
        }
        Ok(())
    }

    pub(super) fn grant(&mut self, channel: u8, power: u8) -> Result<TxGrant, Error> {
        self.refresh_policy()?;
        let grant = TxGrant {
            channel,
            power,
            country: self.domain.country_code,
        };
        self.check_grants(core::slice::from_ref(&grant))?;
        Ok(grant)
    }

    pub(super) fn check_grants(&mut self, grants: &[TxGrant]) -> Result<(), Error> {
        self.refresh_policy()?;
        if grants.iter().any(|g| {
            g.country != self.domain.country_code
                || channel_power(&self.domain, g.channel).is_none_or(|limit| limit < g.power)
        }) {
            return Err(self.deny_policy());
        }
        Ok(())
    }

    pub(in crate::cyw43439) fn check_connection_policy(&mut self) -> Result<(), Error> {
        self.refresh_policy()?;
        if let Some(grant) = self.connection {
            self.check_grants(core::slice::from_ref(&grant))?;
        }
        if self.policy.is_some() && self.bssid.is_some() && self.connection.is_none() {
            return Err(self.deny_policy());
        }
        Ok(())
    }

    /// Check immediately before the retained transport can publish host data.
    pub(in crate::cyw43439) fn send_data(
        &mut self,
        bytes: &[u8],
        priority: u8,
    ) -> Result<(), Error> {
        self.check_connection_policy()?;
        if self.bssid.is_none() {
            return Err(Error::Failed);
        }
        self.runtime.send_data(bytes, priority)
    }

    pub(super) async fn checked_command(
        &mut self,
        grants: &[TxGrant],
        channels: &[u8],
        command: u32,
        bytes: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.check_grants(grants)?;
        self.check_receive_policy(channels)?;
        let result = Fence {
            source: &self.policy,
            domain: &self.domain,
            grants,
            channels,
            initial: false,
        }
        .command(&mut self.runtime, command, bytes)
        .await;
        if matches!(result, Err(Error::Authority)) {
            return Err(self.deny_policy());
        }
        self.check_grants(grants)?;
        self.check_receive_policy(channels)?;
        result
    }
    pub(super) async fn checked_var(
        &mut self,
        grants: &[TxGrant],
        channels: &[u8],
        name: &str,
        value: &[u8],
    ) -> Result<(), Error> {
        let mut bytes = name.as_bytes().to_vec();
        bytes.push(0);
        bytes.extend_from_slice(value);
        self.checked_command(grants, channels, 263, &bytes)
            .await
            .map(|_| ())
    }
    pub(super) async fn tx_command(
        &mut self,
        grant: TxGrant,
        command: u32,
        bytes: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.checked_command(core::slice::from_ref(&grant), &[], command, bytes)
            .await
    }
    pub(super) async fn tx_int(
        &mut self,
        grant: TxGrant,
        command: u32,
        value: u32,
    ) -> Result<(), Error> {
        self.tx_command(grant, command, &value.to_le_bytes())
            .await
            .map(|_| ())
    }
    pub(super) async fn tx_var(
        &mut self,
        grant: TxGrant,
        name: &str,
        value: &[u8],
    ) -> Result<(), Error> {
        self.checked_var(core::slice::from_ref(&grant), &[], name, value)
            .await
    }
}

// Before enabling firmware and before publishing an initialized station, a
// live installation must still be the one used for country/CLM setup.
pub(super) fn check_initial<R: Fullmac>(
    runtime: &mut R,
    source: &Option<Arc<dyn PolicySource>>,
    domain: &Arc<RegulatoryDomain>,
) -> Result<(), Error> {
    if let Some(source) = source {
        if source
            .snapshot()
            .is_none_or(|now| !Arc::ptr_eq(&now, domain))
        {
            runtime.fail();
            runtime.set_link(None);
            return Err(Error::Authority);
        }
    }
    Ok(())
}

// Check again on every resume of a native future. A command may have yielded
// for credits before it publishes its descriptor/FIFO bytes. The old policy
// must not authorize that later publication. A synchronous publish already
// in progress cannot be retracted by a subsequent source change.
struct Fence<'a> {
    source: &'a Option<Arc<dyn PolicySource>>,
    domain: &'a Arc<RegulatoryDomain>,
    grants: &'a [TxGrant],
    channels: &'a [u8],
    initial: bool,
}
impl Fence<'_> {
    fn permits(&self) -> bool {
        let now = if let Some(source) = self.source {
            let Some(now) = source.snapshot() else {
                return false;
            };
            now
        } else {
            self.domain.clone()
        };
        now.country_code == self.domain.country_code
            && (!self.initial || Arc::ptr_eq(&now, self.domain))
            && self
                .channels
                .iter()
                .all(|&ch| channel_ceiling(&now, ch, false).is_some())
            && self.grants.iter().all(|grant| {
                grant.country == now.country_code
                    && channel_power(&now, grant.channel).is_some_and(|power| power >= grant.power)
            })
    }
    async fn command<R: Fullmac>(
        &self,
        runtime: &mut R,
        command: u32,
        bytes: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut future = core::pin::pin!(runtime.command(
            super::Direction::Set,
            command,
            bytes,
            super::MAX_REPLY
        ));
        poll_fn(|cx| {
            if !self.permits() {
                return Poll::Ready(Err(Error::Authority));
            }
            future.as_mut().poll(cx)
        })
        .await
    }
}
pub(super) async fn enable<R: Fullmac>(
    runtime: &mut R,
    source: &Option<Arc<dyn PolicySource>>,
    domain: &Arc<RegulatoryDomain>,
) -> Result<(), Error> {
    let result = Fence {
        source,
        domain,
        grants: &[],
        channels: &[],
        initial: true,
    }
    .command(runtime, super::ioctl::WLC_UP, &0u32.to_le_bytes())
    .await;
    if matches!(result, Err(Error::Authority)) {
        runtime.fail();
        runtime.set_link(None);
    }
    result.map(|_| ())
}
