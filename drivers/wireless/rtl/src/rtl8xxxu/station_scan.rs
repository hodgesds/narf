// SPDX-License-Identifier: GPL-2.0-or-later
//! Associated passive visits over the same native station/key/BA owners.
use super::super::{receive_runtime::ScanConfig, service_runtime::Environment};
use super::*;
#[path = "station_active_scan.rs"]
mod active;
pub(in crate::rtl8xxxu) use active::ActiveRequest;

pub(in crate::rtl8xxxu) struct Observation {
    pub candidate: Candidate,
    pub seen: u64,
    pub generation: u64,
}
impl<C: ControlIo, B: packet_transport::Io> Station<C, B> {
    pub(in crate::rtl8xxxu) fn channel_permission(
        &self,
        channel: u8,
    ) -> Result<power_policy::Permission, Error> {
        self.authority().invoke(|| ()).map_err(Error::Radio)?;
        match self.radio.permission_for_channel(channel) {
            Ok(permission) => Ok(permission),
            Err(_) if channel == self.permission.channel() && channel == self.radio.channel() => {
                self.authority().invoke(|| ()).map_err(Error::Radio)?;
                Ok(self.permission)
            }
            Err(error) => Err(Error::Radio(error)),
        }
    }

    pub(in crate::rtl8xxxu) fn scan_admissible(&self) -> bool {
        self.controlled_port_open()
            && !self
                .security
                .as_ref()
                .is_some_and(Security::handshake_active)
    }

    pub(in crate::rtl8xxxu) async fn passive_scan<E: Environment>(
        &mut self,
        channels: &[u8],
        dwell_ms: u64,
        mandatory: bool,
        environment: &E,
        generation: &mut u64,
    ) -> Result<Vec<Observation>, Error> {
        // scan.c returns home between away visits after HZ/8. The exact
        // cold retune takes real additional time; this bounds the dwell,
        // not a fabricated RF-switch latency or an on-air delivery promise.
        if !self.scan_admissible()
            || channels.is_empty()
            || dwell_ms == 0
            || dwell_ms > 1024
            || mandatory && dwell_ms > 125
        {
            return Err(Error::Profile);
        }
        for &channel in channels {
            let permission = self.channel_permission(channel);
            self.authority().invoke(|| ()).map_err(Error::Radio)?;
            permission?;
        }
        let dwell = dwell_ms.min(125);
        let home_channel = self.radio.channel();
        let authority = self.authority();
        let mut attempt = self.attempt();
        let result = authority
            .fence(
                async {
                    let mut observations = Vec::new();
                    self.scan_drain(environment, *generation, &mut observations)
                        .await?;
                    for &channel in channels {
                        if channel == home_channel {
                            self.scan_home_listen(
                                dwell,
                                environment,
                                *generation,
                                &mut observations,
                            )
                            .await?;
                            continue;
                        }
                        self.scan_drain(environment, *generation, &mut observations)
                            .await?;
                        self.scan_null(true, environment.now_ms())?;
                        // rtl8xxxu has no .flush callback. scan.c::resume leaves
                        // HZ/10 after the best-effort PM1 indication before retune.
                        self.scan_home_listen(100, environment, *generation, &mut observations)
                            .await?;
                        self.scan_drain(environment, *generation, &mut observations)
                            .await?;
                        let config = self.scan_config()?;
                        let home = self
                            .radio
                            .suspend_station(config)
                            .await
                            .map_err(Error::Radio)?;
                        let next = generation.checked_add(1).ok_or(Error::State)?;
                        self.radio
                            .cold_scan_channel(channel, false)
                            .await
                            .map_err(Error::Radio)?;
                        *generation = next;
                        self.scan_away_listen(dwell, environment, *generation, &mut observations)
                            .await?;
                        let next = generation.checked_add(1).ok_or(Error::State)?;
                        self.radio
                            .restore_station(home, self.permission)
                            .await
                            .map_err(Error::Radio)?;
                        *generation = next;
                        let now = environment.now_ms();
                        if now < self.last_now {
                            return Err(Error::State);
                        }
                        // offchannel.c resets connection/beacon monitors on home
                        // return. This does not manufacture a fresh BSS observation.
                        self.last_now = now;
                        self.last_peer = now;
                        self.next_watchdog = now.saturating_add(2000);
                        self.scan_null(false, now)?;
                        // scan.c::suspend gives HZ/5 on home before the next visit.
                        // Normal native DATA/RSNA/reordering progresses in this time.
                        self.scan_home_listen(200, environment, *generation, &mut observations)
                            .await?;
                        self.scan_drain(environment, *generation, &mut observations)
                            .await?;
                    }
                    Ok(observations)
                },
                Error::Radio,
            )
            .await;
        attempt.armed = false;
        if result.is_err() {
            self.fail();
        }
        result
    }

    pub(super) fn scan_config(&self) -> Result<ScanConfig, Error> {
        let management_runtime::Phase::Associated { aid } = self.plan.phase() else {
            return Err(Error::State);
        };
        let operational = self.tx_ba.iter().enumerate().fold(0, |bits, (tid, state)| {
            bits | if matches!(state, Some(TxBa::Operational { .. })) {
                1 << tid
            } else {
                0
            }
        });
        let peer_ampdu = self.plan.peer_ampdu();
        Ok(ScanConfig {
            peer: self.peer(),
            aid,
            short_slot: self.plan.candidate().capability() & 0x400 != 0,
            edca: self.edca,
            ht: self.plan.ht_selected(),
            // Retain every software BA object. Reapply the actual MAC
            // aggregation limits if an originator exchange still exists.
            ampdu: if self.tx_ba.iter().any(Option::is_some) {
                peer_ampdu
            } else {
                None
            },
            tx_ampdu: peer_ampdu.map(|(_, density)| (density, operational)),
        })
    }

    fn scan_null(&mut self, asleep: bool, now: u64) -> Result<(), Error> {
        if !self.transmit_ready()
            || self
                .security
                .as_ref()
                .is_some_and(Security::handshake_active)
        {
            return Err(Error::State);
        }
        let qos = self.plan.wmm().is_some();
        let sequence = if qos {
            0
        } else {
            self.reserve_plain_sequence()?
        };
        let null = super::super::ps_null::Prepared::new(
            self.radio.local().ok_or(Error::State)?,
            self.peer(),
            asleep,
            qos,
            sequence,
        )
        .map_err(Error::Radio)?;
        self.radio.submit_null(&null).map_err(Error::Radio)?;
        // An ordinary retained native receipt, never an invented AP ACK.
        self.pending = Some(Pending {
            kind: Tx::Control,
            deadline: now.saturating_add(1000),
        });
        Ok(())
    }

    fn reserve_plain_sequence(&mut self) -> Result<u16, Error> {
        if let Some(security) = &mut self.security {
            security
                .reserve_plain_control_sequence()
                .map_err(Error::Security)
        } else {
            let sequence = self.sequence;
            self.sequence = (sequence + 1) & 4095;
            Ok(sequence)
        }
    }

    async fn scan_drain<E: Environment>(
        &mut self,
        environment: &E,
        generation: u64,
        observations: &mut Vec<Observation>,
    ) -> Result<(), Error> {
        let until = environment.now_ms().checked_add(1000).ok_or(Error::State)?;
        for _ in 0..20_000 {
            self.scan_home_step(environment, generation, observations)
                .await?;
            if self.transmit_ready()
                && self.edca_pending.is_none()
                && !self.radio.report_time_pending()
                && !self.tx_ba.iter().any(|state| {
                    matches!(state, Some(TxBa::Starting { .. } | TxBa::Stopping { .. }))
                })
            {
                return Ok(());
            }
            if environment.now_ms() >= until {
                return Err(Error::Timeout);
            }
            environment.pause().await;
        }
        Err(Error::Timeout)
    }

    async fn scan_home_step<E: Environment>(
        &mut self,
        environment: &E,
        generation: u64,
        observations: &mut Vec<Observation>,
    ) -> Result<(), Error> {
        let now = environment.now_ms();
        // Preserve all normal home data/EAPOL/BA processing. The scan cache
        // receives only an additional observation of this exact physical copy.
        if let Some(frames) = self.radio.poll().map_err(Error::Radio)? {
            let admitted = self.controlled_port_open();
            let epoch = self.epoch.load(Ordering::Acquire);
            for frame in frames {
                self.scan_observe(&frame, now, generation, observations);
                if self.batch.len() == 256 {
                    return Err(Error::State);
                }
                self.batch.push_back(Captured {
                    frame,
                    admitted,
                    epoch,
                    ordered: false,
                });
            }
        }
        self.step_with_nonce(now, || environment.fresh_nonce().ok())
            .await?;
        if !self.controlled_port_open()
            || self
                .security
                .as_ref()
                .is_some_and(Security::handshake_active)
        {
            return Err(Error::State);
        }
        Ok(())
    }

    async fn scan_home_listen<E: Environment>(
        &mut self,
        ms: u64,
        environment: &E,
        generation: u64,
        observations: &mut Vec<Observation>,
    ) -> Result<(), Error> {
        let until = environment.now_ms().checked_add(ms).ok_or(Error::State)?;
        for _ in 0..20_000 {
            self.scan_home_step(environment, generation, observations)
                .await?;
            if environment.now_ms() >= until {
                return Ok(());
            }
            environment.pause().await;
        }
        Err(Error::Timeout)
    }

    async fn scan_away_listen<E: Environment>(
        &mut self,
        ms: u64,
        environment: &E,
        generation: u64,
        observations: &mut Vec<Observation>,
    ) -> Result<(), Error> {
        let authority = self.radio.authority();
        authority
            .fence(
                async {
                    let until = environment.now_ms().checked_add(ms).ok_or(Error::State)?;
                    for _ in 0..20_000 {
                        let now = environment.now_ms();
                        if now < self.last_now {
                            return Err(Error::State);
                        }
                        self.last_now = now;
                        if let Some(frames) = self.radio.poll().map_err(Error::Radio)? {
                            for frame in frames {
                                // Never feed an away copy into home key/replay/BA state.
                                self.scan_observe(&frame, now, generation, observations);
                            }
                        }
                        if self.radio.recovery_pending() {
                            self.radio.recover().await.map_err(Error::Radio)?;
                        }
                        if now >= until {
                            return Ok(());
                        }
                        environment.pause().await;
                    }
                    Err(Error::Timeout)
                },
                Error::Radio,
            )
            .await
    }

    fn scan_observe(
        &self,
        frame: &Mpdu,
        seen: u64,
        generation: u64,
        observations: &mut Vec<Observation>,
    ) {
        let Some(own) = self.radio.local() else {
            return;
        };
        let Ok(candidate) = Candidate::from_receive_with_phy(
            frame,
            self.radio.channel(),
            own,
            self.radio.ht_local().as_ref(),
        ) else {
            return;
        };
        let observation = Observation {
            candidate,
            seen,
            generation,
        };
        if let Some(entry) = observations
            .iter_mut()
            .find(|entry| entry.candidate.bssid() == observation.candidate.bssid())
        {
            *entry = observation;
        } else {
            if observations.len() == 32 {
                let oldest = observations
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, entry)| entry.seen)
                    .map(|(i, _)| i)
                    .unwrap();
                observations.swap_remove(oldest);
            }
            observations.push(observation);
        }
    }
}
