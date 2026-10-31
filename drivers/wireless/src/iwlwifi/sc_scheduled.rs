//! Retained firmware periodic-scan owner. A netlink waiter owns neither
//! the autonomous emitter nor the DMA necessary to stop it.
use super::*;
use narf_wireless::ap_control::{RadioControlAuthority, RadioEventAuthority};
use narf_wireless::SchedScanRequest;

use super::super::scheduled_wire as wire;

pub(super) struct Owner {
    event: RadioEventAuthority,
    request: SchedScanRequest,
    channels: Vec<u8>,
    cancel: Arc<AtomicBool>,
    epoch: u64,
    results: Vec<(BssInfo, Vec<u8>)>,
}

struct Reply {
    result: Option<Result<(), i32>>,
    waker: Option<Waker>,
}
struct Waiter {
    reply: Arc<IrqSafeSpinLock<Reply>>,
    cancel: Arc<AtomicBool>,
    consumed: bool,
}
impl Future for Waiter {
    type Output = Result<(), i32>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let result = {
            let mut reply = self.reply.lock();
            match reply.result.take() {
                Some(result) => Some(result),
                None => {
                    reply.waker = Some(cx.waker().clone());
                    None
                }
            }
        };
        if let Some(result) = result {
            self.consumed = true;
            Poll::Ready(result)
        } else {
            Poll::Pending
        }
    }
}
impl Drop for Waiter {
    fn drop(&mut self) {
        if !self.consumed {
            self.cancel.store(true, Ordering::Release);
        }
    }
}

pub(super) struct Publication {
    event: RadioEventAuthority,
    source: super::super::runtime::source::Fence,
    epoch: u64,
    generation: Arc<AtomicU64>,
    policy: Option<super::super::mld_policy::Authority>,
    results: Option<Vec<(BssInfo, Vec<u8>)>>,
}
impl Publication {
    pub(super) fn publish(self) {
        let _ = self.source.invoke(|| {
            if self.generation.load(Ordering::Acquire) != self.epoch {
                return Err("retired Intel scheduled scan result generation");
            }
            if let Some(policy) = &self.policy {
                policy.check()?;
            }
            if let Some(results) = self.results {
                self.event.scheduled_scan_results_with_bss(results)
            } else {
                self.event.scheduled_scan_stopped()
            }
            .map_err(|_| "Intel scheduled scan source closed before publication")
        });
    }
}

impl Device {
    pub(super) fn scheduled_support(&self) -> narf_wireless::SchedScanSupport {
        narf_wireless::SchedScanSupport {
            max_match_sets: 8,
            max_ssids: 20,
            max_ie_len: 256,
            max_scan_plans: 2,
            max_plan_interval_secs: 65535,
            max_plan_iterations: 254,
            max_frequencies: self.channels.len() as u16,
            random_mac: true,
        }
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
        let device = self.me.upgrade().ok_or(19)?;
        let mut slot = self.control.try_lock().ok_or(16)?;
        if slot.is_some() {
            return Err(16);
        }
        let reply = Arc::new(IrqSafeSpinLock::new(Reply {
            result: None,
            waker: None,
        }));
        let cancel = Arc::new(AtomicBool::new(false));
        let retained = authority.clone();
        let completion = reply.clone();
        let abandoned = cancel.clone();
        *slot = Some(Work::new(async move {
            let mut state = device.state.lock().await;
            let result = if let Some(request) = request {
                device
                    .start_scheduled(&mut state, &retained, request, abandoned)
                    .await
            } else {
                // A stop attempt survives caller/source revocation. The
                // native owner must still resolve its UID and transport.
                device.retire_scheduled(&mut state).await.map_err(|_| 5)
            };
            let mut reply = completion.lock();
            reply.result = Some(result);
            if let Some(waker) = reply.waker.take() {
                waker.wake();
            }
        }));
        drop(slot);
        let mut waiter = Box::pin(Waiter {
            reply,
            cancel,
            consumed: false,
        });
        poll_fn(|cx| {
            let _ = self.poll_control(cx);
            waiter.as_mut().poll(cx)
        })
        .await
    }

    async fn start_scheduled(
        &self,
        state: &mut State,
        authority: &RadioControlAuthority,
        request: SchedScanRequest,
        cancel: Arc<AtomicBool>,
    ) -> Result<(), i32> {
        authority.check_for(self).map_err(|_| 1)?;
        authority.require_link().map_err(|_| 1)?;
        if self.closing.load(Ordering::Acquire)
            || state.connection.is_some()
            || state.scheduled.is_some()
        {
            return Err(16);
        }
        if state.needs_reset || state.hardware.is_failed() {
            self.recover(state).await.map_err(|_| 5)?;
            // Recovery replaces the generation. An old request cannot arm
            // new firmware merely because the interface name stayed equal.
            authority.check_for(self).map_err(|_| 1)?;
        }
        let channels = if request.frequencies_mhz.is_empty() {
            self.channels.clone()
        } else {
            let mut channels = Vec::new();
            for &requested_frequency in &request.frequencies_mhz {
                let channel = self
                    .channels
                    .iter()
                    .copied()
                    .find(|&channel| wire::frequency(channel) == Some(requested_frequency))
                    .ok_or(22)?;
                if !channels.contains(&channel) {
                    channels.push(channel);
                }
            }
            channels
        };
        let local = if let Some(random) = &request.random_mac {
            let mut bytes = [0; 6];
            narf_crypto::try_fill_random_bytes(&mut bytes).map_err(|_| 5)?;
            bytes[0] = (bytes[0] | 2) & !1;
            for (i, byte) in bytes.iter_mut().enumerate() {
                *byte = (*byte & !random.mask[i]) | (random.addr[i] & random.mask[i]);
            }
            if bytes[0] & 1 != 0 || bytes == [0; 6] {
                return Err(22);
            }
            bytes
        } else {
            self.mac
        };
        // Pure structural preflight precedes the first native mutation.
        let profile = wire::profiles(&request.matches).map_err(|_| 22)?;
        let version = state.hardware.version(1, 0xd).ok_or(95)?.0;
        wire::request(
            version,
            &channels,
            &alloc::vec![false;channels.len()],
            local,
            self.phy,
            &request,
        )
        .map_err(|_| 22)?;
        let epoch = self
            .scan_generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                old.checked_add(2).map(|_| old + 1)
            })
            .map_err(|_| 1)?
            + 1;
        let event = authority.event_authority().map_err(|_| 1)?;
        state.needs_reset = true;
        state.stop_completed = false;
        let result = {
            let native = async {
                let hw = &mut state.hardware;
                hw.clear_rf_policy();
                let mut permitted = alloc::vec![false;channels.len()];
                let mut phy = self.phy;
                if !request.probe_ssids.is_empty() {
                    if let Ok(domain) = self.policy.snapshot() {
                        hw.install_rf_policy(super::super::mld_policy::Authority::Transaction(
                            self.policy.transaction(&domain)?,
                        ))?;
                        let mcc =
                            super::super::connection::regulatory_channels_in_domain(hw, &domain)
                                .await?;
                        let powers: Vec<_> = channels
                            .iter()
                            .map(|&channel| {
                                super::super::connection::channel_power(
                                    &domain,
                                    channel,
                                    &mcc.channels,
                                    true,
                                )
                            })
                            .collect();
                        if let Some(power) = powers.iter().flatten().min() {
                            hw.ensure_platform_power().await?;
                            let mut body = station_api::tx_power(
                                hw.version(1, 0x9f)
                                    .ok_or("scheduled TX power version absent")?
                                    .0,
                                *power,
                            )?;
                            body[0] = 1;
                            hw.command(1, 0x9f, &body).await?;
                        }
                        permitted = powers.iter().map(Option::is_some).collect();
                        phy.he &= mcc.he_allowed;
                    }
                }
                let body = wire::request(version, &channels, &permitted, local, phy, &request)?;
                discard_notifications(hw);
                // Linux MLD sends this fixed API3 layout. The narrow ID is
                // normalized to LONG_GROUP by the HostCommand owner; actual
                // Sc metadata reports command3 in that normalized group.
                hw.command(0, 0x6e, &profile).await?;
                hw.command(1, 0xd, &body).await?;
                Ok::<(), &'static str>(())
            };
            let mut native = Box::pin(native);
            poll_fn(|cx| {
                if cancel.load(Ordering::Acquire)
                    || authority.check_for(self).is_err()
                    || authority.require_link().is_err()
                {
                    return Poll::Ready(Err("Intel scheduled start lost its actual request owner"));
                }
                native.as_mut().poll(cx)
            })
            .await
        };
        if result.is_err() {
            self.stop_locked(state).await;
            return Err(5);
        }
        state.scheduled = Some(Owner {
            event,
            request,
            channels,
            cancel,
            epoch,
            results: Vec::new(),
        });
        state.needs_reset = false;
        Ok(())
    }

    /// RF authority may have vanished. Stopping does not need permission
    /// to emit; executable/PCI command scopes remain checked. If those or
    /// the native UID proof fail, perform the independent physical stop.
    pub(super) async fn retire_scheduled(&self, state: &mut State) -> Result<(), &'static str> {
        let Some(owner) = state.scheduled.take() else {
            return Ok(());
        };
        state.hardware.clear_rf_policy();
        let result = async {
            let mut abort = [0; 8];
            abort[..4].copy_from_slice(&wire::UID.to_le_bytes());
            let reply = state.hardware.command(1, 0xe, &abort).await?;
            if !wire::aborted_reply(&reply.payload)? {
                let deadline = narf_time::Deadline::after_ms(2000);
                loop {
                    let activity = state.hardware.activity();
                    state.hardware.poll()?;
                    if let Some(index) = state.hardware.notifications.iter().position(|p| {
                        p.header.group_id == 0
                            && p.header.cmd == 0xf
                            && p.payload.get(..4) == Some(wire::UID.to_le_bytes().as_slice())
                    }) {
                        wire::complete(
                            &state.hardware.notifications.remove(index).unwrap().payload,
                        )?;
                        break;
                    }
                    if deadline.expired() {
                        return Err("scheduled abort terminal UID timed out");
                    }
                    activity.await;
                }
            }
            discard_notifications(&mut state.hardware);
            Ok(())
        }
        .await;
        // A queued result retains an epoch, not permission after retirement.
        self.scan_generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                old.checked_add(1)
            })
            .ok();
        if result.is_err() {
            self.stop_locked(state).await;
        }
        drop(owner);
        result
    }

    pub(super) fn scheduled_step(self: &Arc<Self>, state: &mut State) -> Vec<Publication> {
        let mut publications = Vec::new();
        let Some(owner) = state.scheduled.as_mut() else {
            return publications;
        };
        let lost = owner.cancel.load(Ordering::Acquire)
            || owner.event.check_for(self.as_ref()).is_err()
            || state
                .hardware
                .source_fence()
                .and_then(|s| s.invoke(|| Ok(())))
                .is_err();
        if lost {
            self.start_scheduled_retirement();
            return publications;
        }
        let mut stopped = false;
        let mut publish = false;
        let mut malformed = false;
        for _ in 0..64 {
            let Some(packet) = state.hardware.notifications.pop_front() else {
                break;
            };
            if packet.header.group_id != 0 {
                continue;
            }
            match packet.header.cmd {
                0xf => match wire::complete(&packet.payload) {
                    Ok(Some(_)) => stopped = true,
                    Ok(None) => {}
                    Err(_) => {
                        malformed = true;
                        break;
                    }
                },
                0xb5 => {
                    if packet.payload.len() < 16 {
                        malformed = true;
                        break;
                    }
                    if packet.payload[..4] == wire::UID.to_le_bytes()
                        && owner
                            .request
                            .matches
                            .first()
                            .is_none_or(|m| m.ssid.is_empty())
                    {
                        publish = true;
                    }
                }
                0xd9 => publish = true,
                0xc1 if packet.receive_queue == 0 => {
                    if let Some((beacon, bss)) =
                        wire::copied_bss(&packet, false, &owner.channels, &owner.request)
                    {
                        if let Some(old) = state
                            .beacons
                            .iter_mut()
                            .find(|old| old.bssid == beacon.bssid)
                        {
                            *old = beacon.clone();
                        } else if state.beacons.len() < 256 {
                            state.beacons.push(beacon.clone());
                        }
                        let entry = (bss, beacon.information_elements);
                        if let Some(old) = owner
                            .results
                            .iter_mut()
                            .find(|old| old.0.bssid == entry.0.bssid)
                        {
                            *old = entry;
                        } else if owner.results.len() < 256 {
                            owner.results.push(entry);
                        }
                    }
                }
                _ => {}
            }
        }
        if malformed {
            self.start_repair(state);
            return publications;
        }
        if publish && !owner.results.is_empty() || stopped {
            publications.push(Publication {
                event: owner.event.clone(),
                source: self.source.clone(),
                epoch: owner.epoch,
                generation: self.scan_generation.clone(),
                policy: if stopped {
                    None
                } else {
                    state.hardware.rf_policy_clone()
                },
                results: if stopped {
                    None
                } else {
                    Some(owner.results.clone())
                },
            });
        }
        if stopped {
            state.scheduled = None;
            state.hardware.clear_rf_policy();
        }
        publications
    }
    fn start_scheduled_retirement(self: &Arc<Self>) {
        let Some(mut control) = self.control.try_lock() else {
            return;
        };
        if control.is_some() {
            return;
        }
        let device = self.clone();
        *control = Some(Work::new(async move {
            let mut state = device.state.lock().await;
            let _ = device.retire_scheduled(&mut state).await;
        }));
    }
}

fn discard_notifications(hw: &mut Hardware) {
    hw.notifications.retain(|p| {
        !(p.header.group_id == 0 && matches!(p.header.cmd, 0xf | 0xc1 | 0xb2 | 0xb5 | 0xd9))
    });
}
