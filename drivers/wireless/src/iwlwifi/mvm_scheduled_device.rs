//! Exact-source API77 idle PNO controls, retained independently of callers.
use super::*;
use narf_wireless::ap_control::{RadioControlAuthority, RadioEventAuthority};
use narf_wireless::{SchedScanRequest, SchedScanSupport};

pub(super) struct Start {
    pub request: SchedScanRequest,
    pub channels: Vec<u8>,
    pub authority: RadioControlAuthority,
    pub cancel: Arc<AtomicBool>,
}
pub(super) struct Control {
    pub native: super::super::mvm_boot::scheduled::Scheduled,
    pub event: RadioEventAuthority,
    pub cancel: Arc<AtomicBool>,
    pub epoch: u64,
}
struct Waiter(Arc<AtomicBool>, bool);
impl Drop for Waiter {
    fn drop(&mut self) {
        if !self.1 {
            self.0.store(true, Ordering::Release);
        }
    }
}
pub(super) struct Delivery {
    source: Source,
    policy: Policy,
    program: super::super::mvm_boot::scheduled::Fence,
    event: RadioEventAuthority,
    generation: Arc<AtomicU64>,
    epoch: u64,
    cancel: Arc<AtomicBool>,
    results: Option<Vec<(BssInfo, Vec<u8>)>>,
}
impl Delivery {
    pub fn publish(self) {
        let _ = self.source.invoke(|| {
            if self.generation.load(Ordering::Acquire) != self.epoch
                || self.cancel.load(Ordering::Acquire)
            {
                return Err("MVM scheduled publication retired");
            }
            if let Some(results) = self.results {
                self.program.invoke(&(self.policy)()?, || {
                    self.event
                        .scheduled_scan_results_with_bss(results)
                        .map_err(|_| "MVM scheduled result source retired")
                })
            } else {
                self.event
                    .scheduled_scan_stopped()
                    .map_err(|_| "MVM scheduled stop source retired")
            }
        });
    }
}
impl Device {
    pub(super) fn scheduled_support(&self) -> Option<SchedScanSupport> {
        let maximum = self.schedule_profiles;
        Some(SchedScanSupport {
            max_match_sets: maximum,
            max_ssids: 20,
            max_ie_len: 256,
            max_scan_plans: 2,
            max_plan_interval_secs: 65535,
            max_plan_iterations: 254,
            max_frequencies: self.channels.len() as u16,
            random_mac: true,
        })
    }
    pub(super) async fn scheduled_control(
        &self,
        authority: &RadioControlAuthority,
        request: Option<SchedScanRequest>,
    ) -> Result<(), i32> {
        authority.check_for(self).map_err(|_| 1)?;
        authority.require_mode(2).map_err(|_| 1)?;
        authority.require_link().map_err(|_| 1)?;
        if !authority.has_reservation() {
            return Err(1);
        }
        if request.is_some() {
            self.recover_failed().await.map_err(|_| 5)?;
            authority.check_for(self).map_err(|_| 1)?;
            authority.require_link().map_err(|_| 1)?;
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let mut waiter = Waiter(cancel.clone(), request.is_none());
        let operation = if let Some(request) = request {
            let channels = if request.frequencies_mhz.is_empty() {
                let domain = (self.environment.policy)().map_err(|_| 5)?;
                self.channels
                    .iter()
                    .copied()
                    .filter(|&channel| super::super::mvm_boot::passive_channel(&domain, channel))
                    .collect()
            } else {
                let mut channels = Vec::new();
                for &frequency in &request.frequencies_mhz {
                    let channel = self
                        .channels
                        .iter()
                        .copied()
                        .find(|&ch| channel_frequency(ch) == frequency)
                        .ok_or(22)?;
                    if !channels.contains(&channel) {
                        channels.push(channel);
                    }
                }
                channels
            };
            Operation::StartScheduled(Box::new(Start {
                request,
                channels,
                authority: authority.clone(),
                cancel,
            }))
        } else {
            Operation::StopScheduled
        };
        let reply = self.begin(operation).map_err(|_| 16)?;
        let result = self.wait(reply).await.map_err(|_| 5)?;
        waiter.1 = true;
        match result {
            Outcome::Done => Ok(()),
            _ => Err(5),
        }
    }
    pub(super) async fn execute_scheduled_start(
        &self,
        owner: &mut Owner,
        slot: &mut Option<Control>,
        start: Start,
    ) -> Result<Outcome, &'static str> {
        if slot.is_some() {
            return Err("MVM scheduled owner already live");
        }
        start
            .authority
            .check_for(self)
            .map_err(|_| "MVM scheduled receiver retired")?;
        let event = start
            .authority
            .event_authority()
            .map_err(|_| "MVM scheduled source retired")?;
        let epoch = self
            .scan_generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                old.checked_add(2).map(|_| old + 1)
            })
            .map_err(|_| "MVM scheduled generation exhausted")?
            + 1;
        let source = if start.request.probe_ssids.is_empty() {
            None
        } else {
            Some((self.environment.scan_power)(owner, &start.channels)?)
        };
        let native = owner
            .scheduled_start_using(&start.channels, start.request, source, || {
                (self.environment.policy)()
            })
            .await?;
        *slot = Some(Control {
            native,
            event,
            cancel: start.cancel,
            epoch,
        });
        Ok(Outcome::Done)
    }
    pub(super) async fn execute_scheduled_stop(
        &self,
        owner: &mut Owner,
        slot: &mut Option<Control>,
    ) -> Result<Outcome, &'static str> {
        if let Some(retained) = slot.take() {
            retained.cancel.store(true, Ordering::Release);
            let generation = self
                .scan_generation
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                    old.checked_add(1)
                })
                .map_err(|_| "MVM scheduled retirement generation exhausted");
            let result = owner.scheduled_stop().await;
            drop(retained);
            result?;
            generation?;
        }
        Ok(Outcome::Done)
    }
    pub(super) fn scheduled_tick(&self, state: &mut State) -> (Vec<Delivery>, bool) {
        let mut deliveries = Vec::new();
        let Some(control) = state.scheduled.as_mut() else {
            return (deliveries, false);
        };
        let Some(owner) = state.owner.as_mut() else {
            return (deliveries, true);
        };
        if control.cancel.load(Ordering::Acquire) || control.event.check_for(self).is_err() {
            return (deliveries, true);
        }
        // Bound every BSS copied in this poll before receiving it. A later
        // match/stop receipt cannot rejuvenate an earlier observation.
        let copied_after = (self.environment.observation_clock)();
        let result = self.source.invoke(|| {
            owner.scheduled_poll(
                &mut control.native,
                &(self.environment.policy)()?,
                copied_after,
            )
        });
        match result {
            Ok(report) => {
                state.scan_time = report.oldest;
                let epoch = if report.stopped {
                    match self.scan_generation.fetch_update(
                        Ordering::AcqRel,
                        Ordering::Acquire,
                        |old| old.checked_add(1),
                    ) {
                        Ok(old) => old + 1,
                        Err(_) => {
                            control.cancel.store(true, Ordering::Release);
                            owner.station_fail();
                            return (deliveries, true);
                        }
                    }
                } else {
                    control.epoch
                };
                if report.stopped || report.results.is_some() {
                    deliveries.push(Delivery {
                        source: self.source.clone(),
                        policy: self.environment.policy.clone(),
                        program: control.native.fence(),
                        event: control.event.clone(),
                        generation: self.scan_generation.clone(),
                        epoch,
                        cancel: control.cancel.clone(),
                        results: if report.stopped { None } else { report.results },
                    });
                }
                if report.stopped {
                    state.scheduled = None;
                }
                (deliveries, false)
            }
            Err(_) => {
                control.cancel.store(true, Ordering::Release);
                owner.station_fail();
                (deliveries, true)
            }
        }
    }
    pub(super) async fn ensure_scheduled_stopped(&self) -> Result<(), &'static str> {
        let active = self
            .state
            .try_lock()
            .ok_or("MVM control busy")?
            .scheduled
            .is_some();
        if active {
            let reply = self.begin(Operation::StopScheduled)?;
            self.wait(reply).await?;
        }
        Ok(())
    }
}
