// SPDX-License-Identifier: GPL-2.0-or-later
//! Per-chip signed power base for the retained station owner.
//!
//! The station's every publication re-derives the channel's transmit
//! permission from the signed per-board calibration and requires it to equal
//! the permission programmed into the hardware. RTL8188EE uses the `NEPC`
//! legacy envelope (`channel_power`) plus its optional HT/protection/
//! tracking/antenna/fallback grants; RTL8821AE uses the `NAPC` envelope
//! (`rtl8821ae::envelope`) and admits none of those 88EE extensions;
//! RTL8192EE uses the `N92E` envelope (`rtl8192ee::envelope`), likewise
//! without any 88EE extension; RTL8192CE / RTL8188CE uses the `N92C`
//! envelope (`rtl8192ce::envelope`), likewise without any 88EE extension;
//! RTL8192DE uses the `N92D` envelope (`rtl8192de::envelope`), likewise
//! without any 88EE extension.
use super::{
    channel_power, prepare, rtl8192ce::envelope as ce92, rtl8192de::envelope as de92,
    rtl8192ee::envelope as ee92, rtl8821ae::envelope,
};
use alloc::sync::Arc;

#[derive(Clone)]
pub(crate) enum Base {
    Rtl8188ee(Arc<channel_power::Calibration>),
    Rtl8821ae(Arc<envelope::Calibration>),
    Rtl8192ee(Arc<ee92::Calibration>),
    Rtl8192ce(Arc<ce92::Calibration>),
    Rtl8192de(Arc<de92::Calibration>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Grant {
    Rtl8188ee(channel_power::Permission),
    Rtl8821ae(envelope::Permission),
    Rtl8192ee(ee92::Permission),
    Rtl8192ce(ce92::Permission),
    Rtl8192de(de92::Permission),
}

impl Grant {
    pub(crate) fn channel(&self) -> u8 {
        match self {
            Self::Rtl8188ee(p) => p.channel(),
            Self::Rtl8821ae(p) => p.channel(),
            Self::Rtl8192ee(p) => p.channel(),
            Self::Rtl8192ce(p) => p.channel(),
            Self::Rtl8192de(p) => p.channel(),
        }
    }
    /// The 88EE permission the 88EE-only grants are checked against.
    pub(crate) fn ee(&self) -> Option<channel_power::Permission> {
        match self {
            Self::Rtl8188ee(p) => Some(*p),
            Self::Rtl8821ae(_) | Self::Rtl8192ee(_) | Self::Rtl8192ce(_) | Self::Rtl8192de(_) => {
                None
            }
        }
    }
}

impl Base {
    /// The 88EE calibration that HT/protection/tracking/antenna/fallback
    /// grants are minted over; `None` for 8821AE (none are admitted).
    pub(crate) fn ee(&self) -> Option<&Arc<channel_power::Calibration>> {
        match self {
            Self::Rtl8188ee(base) => Some(base),
            Self::Rtl8821ae(_) | Self::Rtl8192ee(_) | Self::Rtl8192ce(_) | Self::Rtl8192de(_) => {
                None
            }
        }
    }
    /// The 8821AE `NAPC` calibration.
    pub(crate) fn rtl8821ae(&self) -> Option<&Arc<envelope::Calibration>> {
        match self {
            Self::Rtl8821ae(base) => Some(base),
            Self::Rtl8188ee(_) | Self::Rtl8192ee(_) | Self::Rtl8192ce(_) | Self::Rtl8192de(_) => {
                None
            }
        }
    }
    /// The 8192EE `N92E` calibration.
    pub(crate) fn rtl8192ee(&self) -> Option<&Arc<ee92::Calibration>> {
        match self {
            Self::Rtl8192ee(base) => Some(base),
            Self::Rtl8188ee(_) | Self::Rtl8821ae(_) | Self::Rtl8192ce(_) | Self::Rtl8192de(_) => {
                None
            }
        }
    }
    /// The 8192CE / 8188CE `N92C` calibration.
    pub(crate) fn rtl8192ce(&self) -> Option<&Arc<ce92::Calibration>> {
        match self {
            Self::Rtl8192ce(base) => Some(base),
            Self::Rtl8188ee(_) | Self::Rtl8821ae(_) | Self::Rtl8192ee(_) | Self::Rtl8192de(_) => {
                None
            }
        }
    }
    /// The 8192DE `N92D` calibration.
    pub(crate) fn rtl8192de(&self) -> Option<&Arc<de92::Calibration>> {
        match self {
            Self::Rtl8192de(base) => Some(base),
            Self::Rtl8188ee(_) | Self::Rtl8821ae(_) | Self::Rtl8192ee(_) | Self::Rtl8192ce(_) => {
                None
            }
        }
    }
    /// Re-derive `current` under `domain`: the 88EE channel permission, or
    /// the 8821AE permission at the same operating point (band, width,
    /// primary), so an admitted 40 MHz grant is re-derived as 40 MHz.
    pub(crate) fn regrant(
        &self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        current: Grant,
    ) -> Result<Grant, channel_power::Error> {
        match (self, current) {
            (Self::Rtl8188ee(base), _) => base
                .permission(domain, current.channel())
                .map(Grant::Rtl8188ee),
            (Self::Rtl8821ae(base), Grant::Rtl8821ae(p)) => base
                .permission_for(domain, p.operating())
                .map(Grant::Rtl8821ae),
            (Self::Rtl8192ee(base), Grant::Rtl8192ee(p)) => base
                .permission_for(domain, p.operating())
                .map(Grant::Rtl8192ee),
            (Self::Rtl8192ce(base), Grant::Rtl8192ce(p)) => base
                .permission_for(domain, p.operating())
                .map(Grant::Rtl8192ce),
            (Self::Rtl8192de(base), Grant::Rtl8192de(p)) => base
                .permission_for(domain, p.operating())
                .map(Grant::Rtl8192de),
            (
                Self::Rtl8821ae(_) | Self::Rtl8192ee(_) | Self::Rtl8192ce(_) | Self::Rtl8192de(_),
                _,
            ) => Err(channel_power::Error::Identity),
        }
    }
    pub(crate) fn with_current<T>(
        &self,
        operation: impl FnOnce() -> Result<T, prepare::Error>,
    ) -> Result<T, prepare::Error> {
        match self {
            Self::Rtl8188ee(base) => base.with_current(operation),
            Self::Rtl8821ae(base) => base.with_current(operation),
            Self::Rtl8192ee(base) => base.with_current(operation),
            Self::Rtl8192ce(base) => base.with_current(operation),
            Self::Rtl8192de(base) => base.with_current(operation),
        }
    }
}

/// 8821AE analogue of `ht::wait` without 88EE grants: every poll of
/// `future` runs inside the envelope's current authority after the current
/// host policy re-derived exactly `grant`.
pub(crate) async fn wait_rtl8821ae<F: core::future::Future<Output = Result<(), prepare::Error>>>(
    base: Arc<envelope::Calibration>,
    grant: envelope::Permission,
    environment: &impl prepare::station::Environment,
    future: F,
) -> Result<(), prepare::Error> {
    let mut future = core::pin::pin!(future);
    core::future::poll_fn(|cx| {
        let operation = || {
            let domain = environment
                .domain()
                .map_err(|_| prepare::Error::Power(channel_power::Error::Policy))?;
            if base
                .permission_for(&domain, grant.operating())
                .map_err(prepare::Error::Power)?
                != grant
            {
                return Err(prepare::Error::State);
            }
            Ok(future.as_mut().poll(cx))
        };
        match base.with_current(operation) {
            Ok(core::task::Poll::Ready(result)) => core::task::Poll::Ready(result),
            Ok(core::task::Poll::Pending) => core::task::Poll::Pending,
            Err(error) => core::task::Poll::Ready(Err(error)),
        }
    })
    .await
}

/// 8192EE analogue of [`wait_rtl8821ae`]: every poll of `future` runs
/// inside the `N92E` envelope's current authority after the current host
/// policy re-derived exactly `grant` (same operating point).
pub(crate) async fn wait_rtl8192ee<F: core::future::Future<Output = Result<(), prepare::Error>>>(
    base: Arc<ee92::Calibration>,
    grant: ee92::Permission,
    environment: &impl prepare::station::Environment,
    future: F,
) -> Result<(), prepare::Error> {
    let mut future = core::pin::pin!(future);
    core::future::poll_fn(|cx| {
        let operation = || {
            let domain = environment
                .domain()
                .map_err(|_| prepare::Error::Power(channel_power::Error::Policy))?;
            if base
                .permission_for(&domain, grant.operating())
                .map_err(prepare::Error::Power)?
                != grant
            {
                return Err(prepare::Error::State);
            }
            Ok(future.as_mut().poll(cx))
        };
        match base.with_current(operation) {
            Ok(core::task::Poll::Ready(result)) => core::task::Poll::Ready(result),
            Ok(core::task::Poll::Pending) => core::task::Poll::Pending,
            Err(error) => core::task::Poll::Ready(Err(error)),
        }
    })
    .await
}

/// 8192CE / 8188CE analogue of [`wait_rtl8821ae`]: every poll of `future`
/// runs inside the `N92C` envelope's current authority after the current host
/// policy re-derived exactly `grant` (same operating point).
pub(crate) async fn wait_rtl8192ce<F: core::future::Future<Output = Result<(), prepare::Error>>>(
    base: Arc<ce92::Calibration>,
    grant: ce92::Permission,
    environment: &impl prepare::station::Environment,
    future: F,
) -> Result<(), prepare::Error> {
    let mut future = core::pin::pin!(future);
    core::future::poll_fn(|cx| {
        let operation = || {
            let domain = environment
                .domain()
                .map_err(|_| prepare::Error::Power(channel_power::Error::Policy))?;
            if base
                .permission_for(&domain, grant.operating())
                .map_err(prepare::Error::Power)?
                != grant
            {
                return Err(prepare::Error::State);
            }
            Ok(future.as_mut().poll(cx))
        };
        match base.with_current(operation) {
            Ok(core::task::Poll::Ready(result)) => core::task::Poll::Ready(result),
            Ok(core::task::Poll::Pending) => core::task::Poll::Pending,
            Err(error) => core::task::Poll::Ready(Err(error)),
        }
    })
    .await
}

/// 8192DE analogue of [`wait_rtl8821ae`]: every poll of `future` runs
/// inside the `N92D` envelope's current authority after the current host
/// policy re-derived exactly `grant` (same operating point).
pub(crate) async fn wait_rtl8192de<F: core::future::Future<Output = Result<(), prepare::Error>>>(
    base: Arc<de92::Calibration>,
    grant: de92::Permission,
    environment: &impl prepare::station::Environment,
    future: F,
) -> Result<(), prepare::Error> {
    let mut future = core::pin::pin!(future);
    core::future::poll_fn(|cx| {
        let operation = || {
            let domain = environment
                .domain()
                .map_err(|_| prepare::Error::Power(channel_power::Error::Policy))?;
            if base
                .permission_for(&domain, grant.operating())
                .map_err(prepare::Error::Power)?
                != grant
            {
                return Err(prepare::Error::State);
            }
            Ok(future.as_mut().poll(cx))
        };
        match base.with_current(operation) {
            Ok(core::task::Poll::Ready(result)) => core::task::Poll::Ready(result),
            Ok(core::task::Poll::Pending) => core::task::Poll::Pending,
            Err(error) => core::task::Poll::Ready(Err(error)),
        }
    })
    .await
}
