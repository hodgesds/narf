// SPDX-License-Identifier: GPL-2.0-or-later
//! Station WoWLAN host state and the system-sleep holder (Linux `wow.c`
//! `ath10k_wow_op_{suspend,resume}` under `conf_mutex`).
//!
//! The holder task owns the Radio mutex from the first WoW command until the
//! firmware's wake report: while the target is in WoW (and the function may
//! be in D3) no worker, control path or recovery can reach its BAR/CE/WMI.
use super::*;
use core::task::{Poll, Waker};
use narf_wireless::{WowlanConfig, WowlanSupport};
use wmi_runtime::wow;

pub(super) struct Host {
    support: Option<WowlanSupport>,
    decap: wow::Decap,
    config: IrqSafeSpinLock<Option<WowlanConfig>>,
    report: IrqSafeSpinLock<Option<wow::WakeReport>>,
}
impl Host {
    pub(super) fn new(support: Option<WowlanSupport>, decap: wow::Decap) -> Self {
        Self {
            support,
            decap,
            config: IrqSafeSpinLock::new(None),
            report: IrqSafeSpinLock::new(None),
        }
    }
}

/// A single-value hand-off between the PM caller and the holder task.
struct Slot<V> {
    inner: IrqSafeSpinLock<(Option<V>, Option<Waker>)>,
}
impl<V> Slot<V> {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: IrqSafeSpinLock::new((None, None)),
        })
    }
    fn put(&self, value: V) {
        let waker = {
            let mut inner = self.inner.lock();
            inner.0 = Some(value);
            inner.1.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
    async fn take(&self) -> V {
        core::future::poll_fn(|cx| {
            let mut inner = self.inner.lock();
            match inner.0.take() {
                Some(value) => Poll::Ready(value),
                None => {
                    inner.1 = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        })
        .await
    }
}

/// A WoW-armed generation awaiting system resume.
pub(in crate::ath10k) struct Suspended<T: Hif + HostMemory + HttMemory> {
    device: Arc<Device<T>>,
    resume: Arc<Slot<()>>,
    resumed: Arc<Slot<Result<wow::WakeReport, Error>>>,
}

fn transport(error: super::super::bmi::BmiError) -> Error {
    Error::Htt(super::super::htt_runtime::Error::from(
        super::super::control::Error::from(error),
    ))
}

impl<T: Hif + HostMemory + HttMemory + Send + 'static> Device<T> {
    pub(in crate::ath10k) fn wowlan_support(&self) -> Option<WowlanSupport> {
        self.wow.support
    }
    /// Whether the retained advertisement carries NET_DETECT
    /// (`WMI_TLV_SERVICE_NLO` was present at init).
    fn nlo_supported(&self) -> bool {
        self.wow
            .support
            .is_some_and(|support| support.net_detect_max_match_sets > 0)
    }
    /// `nl80211_set_wowlan`: re-validated exactly as suspend will program it.
    pub(in crate::ath10k) fn set_wowlan(&self, config: Option<WowlanConfig>) -> Result<(), i32> {
        if self.wow.support.is_none() {
            return Err(narf_wireless::EOPNOTSUPP);
        }
        if let Some(config) = &config {
            wow::Program::new(config, self.wow.decap, self.nlo_supported()).map_err(|_| 22)?;
            // EINVAL
        }
        *self.wow.config.lock() = config;
        Ok(())
    }
    pub(in crate::ath10k) fn wowlan_config(&self) -> Option<WowlanConfig> {
        self.wow.config.lock().clone()
    }
    /// The last WoW resume's firmware wake report.
    pub(in crate::ath10k) fn wowlan_wakeup(&self) -> Option<wow::WakeReport> {
        self.wow.report.lock().clone()
    }
    /// mac80211 `ieee80211_suspend` with a WoWLAN configuration ->
    /// `ath10k_wow_op_suspend`. `Ok(None)`: no retained configuration, not a
    /// station, or not associated without a net-detect configuration
    /// (NARF, like iwlwifi without net-detect, then takes the ordinary
    /// suspend). An unassociated station with net-detect arms WoW on its
    /// home vdev (Linux programs `ath10k_vif_wow_set_wakeups` on every STA
    /// `arvif`, associated or not). `Err`: Linux's
    /// "return 1" fallback; the Radio is left failed for retirement.
    /// The returned holder future must be spawned by a caller with a
    /// concrete transport (its Send-ness is that transport's), then
    /// [`Arming::armed`] awaited.
    #[allow(clippy::type_complexity)]
    pub(in crate::ath10k) fn wow_suspend(
        self: &Arc<Self>,
    ) -> Result<Option<(Arming<T>, impl core::future::Future<Output = ()> + 'static)>, Error> {
        let Some(config) = self.wow.config.lock().clone() else {
            return Ok(None);
        };
        if self.wow.support.is_none()
            || self.mode.load(Ordering::Acquire) != 2
            || self.closed.load(Ordering::Acquire)
        {
            return Ok(None);
        }
        let program = wow::Program::new(&config, self.wow.decap, self.nlo_supported())?;
        // Disconnected net-detect: only the NLO wake is meaningful without
        // an association; anything else suspends ordinarily.
        if !self.link_up() && program.nlo.is_none() {
            return Ok(None);
        }
        let arming = Arming {
            device: self.clone(),
            armed: Slot::new(),
            resume: Slot::new(),
            resumed: Slot::new(),
        };
        let holder = self.clone();
        let (armed_tx, resume_rx, resumed_tx) = (
            arming.armed.clone(),
            arming.resume.clone(),
            arming.resumed.clone(),
        );
        let task = async move {
            let mut radio = holder.radio.lock().await;
            let result = async {
                radio
                    .wow_suspend(&program, || holder.policy.current())
                    .await?;
                radio
                    .htt
                    .wmi
                    .htc
                    .transport
                    .wow_suspend_hif()
                    .map_err(transport)
            }
            .await;
            if result.is_err() {
                radio.fail_station_data();
            }
            let ok = result.is_ok();
            armed_tx.put(result);
            if !ok {
                return;
            }
            resume_rx.take().await;
            let result = async {
                radio
                    .htt
                    .wmi
                    .htc
                    .transport
                    .wow_resume_hif()
                    .map_err(transport)?;
                radio.wow_resume().await
            }
            .await;
            if result.is_err() {
                radio.fail_station_data();
            }
            resumed_tx.put(result);
        };
        Ok(Some((arming, task)))
    }
}

/// A WoW suspend whose holder task is running but not yet acknowledged.
pub(in crate::ath10k) struct Arming<T: Hif + HostMemory + HttMemory> {
    device: Arc<Device<T>>,
    armed: Arc<Slot<Result<(), Error>>>,
    resume: Arc<Slot<()>>,
    resumed: Arc<Slot<Result<wow::WakeReport, Error>>>,
}
impl<T: Hif + HostMemory + HttMemory + Send + 'static> Arming<T> {
    /// WOW_ENABLE acknowledged and the bus suspended, else Linux's
    /// "return 1" fallback error (the holder has released the Radio).
    pub(in crate::ath10k) async fn armed(self) -> Result<Suspended<T>, Error> {
        self.armed.take().await?;
        Ok(Suspended {
            device: self.device,
            resume: self.resume,
            resumed: self.resumed,
        })
    }
}

impl<T: Hif + HostMemory + HttMemory + Send + 'static> Suspended<T> {
    /// `ath10k_wow_op_resume`. `Ok(report)` keeps the association and its
    /// host PN/replay state; `Err` (transport, timeout, or a wake that lost
    /// the connection) requires the caller's full restart, as Linux's
    /// RESTARTING + `ieee80211_reconfig` does.
    pub(in crate::ath10k) async fn resume(self) -> Result<wow::WakeReport, Error> {
        self.resume.put(());
        let result = self.resumed.take().await;
        *self.device.wow.report.lock() = result.as_ref().ok().cloned();
        let report = result?;
        if report.connection_lost() {
            return Err(Error::Failed);
        }
        self.device.kick();
        Ok(report)
    }
    pub(in crate::ath10k) fn device(&self) -> &Arc<Device<T>> {
        &self.device
    }
}
