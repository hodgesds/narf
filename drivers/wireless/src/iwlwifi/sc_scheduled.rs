//! Retained firmware periodic-scan owner. A netlink waiter owns neither
//! the autonomous emitter nor the DMA necessary to stop it.
use super::*;
use narf_wireless::ap_control::{RadioControlAuthority, RadioEventAuthority};
use narf_wireless::SchedScanRequest;

use super::super::scheduled_wire as wire;

pub(super) struct Owner {
    event: RadioEventAuthority,
    request: SchedScanRequest,
    channels: Vec<super::super::native_band::Channel>,
    cancel: Arc<AtomicBool>,
    epoch: u64,
    results: Vec<(BssInfo, Vec<u8>)>,
    // MVM periodic scan remains idle-only; MLD uses the existing home link.
    associated: bool,
    scan: Option<super::super::mld_policy::ScanAuthority>,
}

/// Clone under State, check the actual source without State, then match the
/// same private owner after reacquiring State. No shared callback can recurse
/// into a native lock, and a successor can never inherit an earlier result.
pub(super) struct Currentness {
    event: RadioEventAuthority,
    cancel: Arc<AtomicBool>,
    epoch: u64,
}
impl Currentness {
    pub(super) fn current(&self, device: &Device) -> bool {
        !self.cancel.load(Ordering::Acquire) && self.event.check_for(device).is_ok()
    }
    pub(super) fn matches(&self, state: &State) -> bool {
        state.scheduled.as_ref().is_some_and(|owner| {
            owner.epoch == self.epoch && Arc::ptr_eq(&owner.cancel, &self.cancel)
        })
    }
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
    generation: Arc<super::super::scheduled_epoch::Epoch>,
    cancel: Arc<AtomicBool>,
    policy: Option<super::super::mld_policy::Authority>,
    results: Option<Vec<(BssInfo, Vec<u8>)>>,
}
impl Publication {
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn epoch_for_test(&self) -> u64 {
        self.epoch
    }
    pub(super) fn publish(self) {
        let _ = self.generation.publish(self.epoch, || {
            self.source.invoke(|| {
                if self.cancel.load(Ordering::Acquire) {
                    return Err("Intel scheduled request canceled before publication");
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
            })
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
            max_frequencies: (self.channels.len() + self.six_channels.len()) as u16,
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
            || state.scheduled.is_some()
            || state.hardware.p2p_started()
        {
            return Err(16);
        }
        let associated = state.connection.is_some();
        if associated
            && (!state.hardware.uses_mld_station_protocol()
                || state.connection.as_ref().is_some_and(|c| !c.authorized))
        {
            // Linux mvm/mac80211 requires cfg.idle. Only the admitted MLD
            // consumer supports concurrent serving-link periodic scanning.
            return Err(16);
        }
        if state.needs_reset || state.hardware.is_failed() {
            self.recover(state).await.map_err(|_| 5)?;
            // Recovery replaces the generation. An old request cannot arm
            // new firmware merely because the interface name stayed equal.
            authority.check_for(self).map_err(|_| 1)?;
        }
        use super::super::native_band::{Band, Channel};
        let supported: Vec<_> = self
            .channels
            .iter()
            .filter_map(|&ch| Channel::legacy(ch))
            .chain(self.six_channels.iter().copied())
            .collect();
        let mut channels = if request.frequencies_mhz.is_empty() {
            supported.clone()
        } else {
            let mut channels = Vec::new();
            for &frequency in &request.frequencies_mhz {
                let channel = supported
                    .iter()
                    .copied()
                    .find(|ch| ch.frequency() == frequency)
                    .ok_or(22)?;
                if !channels.contains(&channel) {
                    channels.push(channel);
                }
            }
            channels
        };
        // Linux removes non-PSC6GHz from periodic scans and transmits no
        // probes on the surviving6GHz entries. Geometry grants no RF right.
        channels.retain(|ch| ch.band != Band::Six || ch.number % 16 == 5);
        if channels.is_empty() {
            return Err(22);
        }
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
        wire::request_channels(
            version,
            &channels,
            &alloc::vec![false;channels.len()],
            local,
            self.phy,
            &request,
        )
        .map_err(|_| 22)?;
        let epoch = self.scan_generation.begin().map_err(|_| 1)?;
        let event = authority.event_authority().map_err(|_| 1)?;
        let home = state
            .connection
            .as_ref()
            .map(Connection::regulatory_program);
        let scan = if associated {
            let domain = self.policy.snapshot().map_err(|_| 1)?;
            Some(
                super::super::mld_policy::ScanAuthority::new(
                    self.policy.transaction(&domain).map_err(|_| 1)?,
                    self.me.clone(),
                    event.clone(),
                    cancel.clone(),
                )
                .map_err(|_| 1)?,
            )
        } else {
            None
        };
        state.needs_reset = true;
        state.stop_completed = false;
        let result = {
            let native = async {
                let hw = &mut state.hardware;
                if let (Some(home), Some(scan)) = (&home, &scan) {
                    let fence = self.policy.bind(home.clone())?;
                    hw.install_rf_policy(super::super::mld_policy::Authority::StationAndScan {
                        home: fence,
                        scan: scan.clone(),
                    })?;
                } else {
                    hw.clear_rf_policy();
                }
                let mut permitted = alloc::vec![false;channels.len()];
                let mut phy = self.phy;
                if !request.probe_ssids.is_empty() {
                    if let Ok(domain) = self.policy.snapshot() {
                        if !associated {
                            hw.install_rf_policy(
                                super::super::mld_policy::Authority::Transaction(
                                    self.policy.transaction(&domain)?,
                                ),
                            )?;
                        }
                        let mcc =
                            super::super::connection::regulatory_channels_in_domain(hw, &domain)
                                .await?;
                        if let Some(home) = &home {
                            // A correlated response updates current facts for every
                            // old home capture, preserving its original geometry.
                            home.refresh_mcc(&domain, mcc.clone())?;
                        }
                        let powers: Vec<_> = channels
                            .iter()
                            .map(|&channel| {
                                if channel.band == Band::Six {
                                    None
                                } else {
                                    super::super::connection::channel_power(
                                        &domain,
                                        channel.number,
                                        &mcc.channels,
                                        true,
                                    )
                                }
                            })
                            .collect();
                        if let Some(power) = powers.iter().flatten().min() {
                            // SET_DEVICE is a lasting additional global bound.
                            // Never loosen the existing serving-link ceiling.
                            let power = home
                                .as_ref()
                                .map_or(*power, |home| (*power).min(home.power()));
                            hw.ensure_platform_power().await?;
                            let mut body = station_api::tx_power(
                                hw.version(1, 0x9f)
                                    .ok_or("scheduled TX power version absent")?
                                    .0,
                                power,
                            )?;
                            body[0] = 1;
                            let receipt = hw.command(1, 0x9f, &body).await?;
                            if !receipt.payload.is_empty() {
                                return Err("scheduled global power receipt ambiguous");
                            }
                        }
                        permitted = powers.iter().map(Option::is_some).collect();
                        phy.he &= mcc.he_allowed;
                    }
                }
                let mut body =
                    wire::request_channels(version, &channels, &permitted, local, phy, &request)?;
                if associated {
                    // scan.h GENERAL_PARAMS_API_VER_12: link0 is our actual
                    // single serving link; WILD timing for the current low-load
                    // owner, with no additional host PHY or channel switch.
                    body[11] = 0;
                    body[20..24].copy_from_slice(&120u32.to_le_bytes());
                    body[28..32].copy_from_slice(&30u32.to_le_bytes());
                }
                discard_notifications(hw, associated);
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
            associated,
            scan,
        });
        state.needs_reset = false;
        Ok(())
    }

    /// Forced transport retirement must close copied passive results too:
    /// their firmware/caller grants can remain current after the scanner is
    /// stopped. Cancellation and the private gate precede dropping ownership.
    pub(super) fn abandon_scheduled(&self, state: &mut State) {
        if let Some(owner) = state.scheduled.take() {
            owner.cancel.store(true, Ordering::Release);
            // A live START reserved its retirement before publication. Even
            // exhaustion cannot reopen a copy because cancellation is sticky.
            let _ = self.scan_generation.retire();
        }
    }

    /// RF authority may have vanished. Stopping does not need permission
    /// to emit; executable/PCI command scopes remain checked. If those or
    /// the native UID proof fail, perform the independent physical stop.
    pub(super) async fn retire_scheduled(&self, state: &mut State) -> Result<(), &'static str> {
        let Some(owner) = state.scheduled.take() else {
            return Ok(());
        };
        owner.cancel.store(true, Ordering::Release);
        // Removing scan authority must not invalidate live home captures. The
        // original serving program still proves every unchanged station fact.
        let restored = if owner.associated {
            self.install_station_policy(state)
        } else {
            state.hardware.clear_rf_policy();
            Ok(())
        };
        if let Some(scan) = &owner.scan {
            scan.invalidate();
        }
        let result = async {
            restored?;
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
            discard_notifications(&mut state.hardware, owner.associated);
            Ok(())
        }
        .await;
        // A queued result retains an epoch, not permission after retirement.
        let generation = self.scan_generation.retire();
        let result = result.and_then(|()| generation.map(|_| ()));
        if result.is_err() {
            self.stop_locked(state).await;
        }
        drop(owner);
        result
    }

    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn scheduled_step(self: &Arc<Self>, state: &mut State) -> Vec<Publication> {
        self.scheduled_step_with_budget(state).0
    }
    pub(super) fn scheduled_step_with_budget(
        self: &Arc<Self>,
        state: &mut State,
    ) -> (Vec<Publication>, usize) {
        let mut publications = Vec::new();
        let Some(owner) = state.scheduled.as_mut() else {
            return (publications, 0);
        };
        // The actual event/socket check ran outside State in step_owned and
        // was matched to this exact epoch after reacquiring State.
        let lost = owner.cancel.load(Ordering::Acquire);
        if lost {
            self.start_scheduled_retirement();
            return (publications, 0);
        }
        let mut stopped = false;
        let mut publish = false;
        let mut malformed = false;
        let mut index = 0;
        for _ in 0..64 {
            let Some(packet) = state.hardware.notifications.get(index) else {
                break;
            };
            let consumed = packet.header.group_id == 0
                && matches!(packet.header.cmd, 0xf | 0xb2 | 0xb5 | 0xd9);
            let copy = packet.header.group_id == 0
                && packet.header.cmd == 0xc1
                && packet.receive_queue == 0;
            if !consumed && !copy {
                if owner.associated {
                    index += 1;
                } else {
                    state.hardware.notifications.remove(index);
                }
                continue;
            }
            if copy {
                // Parse only scan facts from the borrowed fallback MPDU. Data
                // packets incur no duplicate allocation or owner replacement.
                let copied = wire::copied_bss_channels(
                    packet,
                    false,
                    state.hardware.band_in_rx_supported(),
                    &owner.channels,
                    &owner.request,
                );
                if owner.associated {
                    index += 1;
                } else {
                    state.hardware.notifications.remove(index);
                }
                if let Some((beacon, bss)) = copied {
                    if let Some(old) = state.beacons.iter_mut().find(|old| {
                        old.bssid == beacon.bssid
                            && old.band == beacon.band
                            && old.channel == beacon.channel
                    }) {
                        *old = beacon.clone();
                    } else if state.beacons.len() < 256 {
                        state.beacons.push(beacon.clone());
                    }
                    let entry = (bss, beacon.information_elements);
                    if let Some(old) = owner.results.iter_mut().find(|old| {
                        old.0.bssid == entry.0.bssid && old.0.frequency_mhz == entry.0.frequency_mhz
                    }) {
                        *old = entry;
                    } else if owner.results.len() < 256 {
                        owner.results.push(entry);
                    }
                }
                continue;
            }
            let packet = state.hardware.notifications.remove(index).unwrap();
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
                _ => {}
            }
        }
        if malformed {
            self.start_repair(state);
            return (publications, 0);
        }
        let epoch = if stopped {
            match self.scan_generation.retire() {
                Ok(epoch) => epoch,
                Err(_) => {
                    self.start_repair(state);
                    return (publications, 0);
                }
            }
        } else {
            owner.epoch
        };
        if publish && !owner.results.is_empty() || stopped {
            publications.push(Publication {
                event: owner.event.clone(),
                source: self.source.clone(),
                epoch,
                generation: self.scan_generation.clone(),
                cancel: owner.cancel.clone(),
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
            let owner = state.scheduled.take().unwrap();
            let restored = if owner.associated {
                self.install_station_policy(state)
            } else {
                state.hardware.clear_rf_policy();
                Ok(())
            };
            if let Some(scan) = &owner.scan {
                scan.invalidate();
            }
            if restored.is_err() {
                publications.clear();
                self.start_repair(state);
            }
        }
        // Only this preserved prefix has been inspected for scan records.
        // The station may consume that prefix; a later UID notification or
        // BSS must stay queued for the next scan pass, never fall through to
        // Connection's unrelated packet decoder.
        (publications, index)
    }
    pub(super) fn scheduled_currentness(&self, state: &State) -> Option<Currentness> {
        state.scheduled.as_ref().map(|owner| Currentness {
            event: owner.event.clone(),
            cancel: owner.cancel.clone(),
            epoch: owner.epoch,
        })
    }
    pub(super) fn station_policy_with_scan(
        &self,
        state: &State,
        home: super::super::mld_policy::Fence,
    ) -> super::super::mld_policy::Authority {
        if let Some(scan) = state
            .scheduled
            .as_ref()
            .and_then(|owner| owner.scan.clone())
        {
            super::super::mld_policy::Authority::StationAndScan { home, scan }
        } else {
            super::super::mld_policy::Authority::Station(home)
        }
    }
    pub(super) fn start_scheduled_retirement(self: &Arc<Self>) {
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

fn discard_notifications(hw: &mut Hardware, associated: bool) {
    hw.notifications.retain(|p| {
        !(p.header.group_id == 0
            && (matches!(p.header.cmd, 0xf | 0xb2 | 0xb5 | 0xd9)
                || !associated && p.header.cmd == 0xc1))
    });
}
