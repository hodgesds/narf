// SPDX-License-Identifier: GPL-2.0-or-later
//! Associated active visits, using the same private idle probe publication
//! path only after the bound physical receiver has actually cold-restarted.
use super::*;
use crate::rtl8xxxu::probe_runtime::Prepared;

pub(in crate::rtl8xxxu) struct ActiveRequest<'a> {
    pub channels: &'a [u8],
    pub dwell_ms: u64,
    pub mandatory: bool,
    pub ssid: &'a [u8],
    pub extra: &'a [u8],
}
impl<C: ControlIo, B: packet_transport::Io> Station<C, B> {
    pub(in crate::rtl8xxxu) async fn active_scan<E: Environment>(
        &mut self,
        request: ActiveRequest<'_>,
        environment: &E,
        generation: &mut u64,
    ) -> Result<Vec<Observation>, Error> {
        if !self.scan_admissible()
            || request.channels.is_empty()
            || !(1..=1024).contains(&request.dwell_ms)
            || request.mandatory && request.dwell_ms > 125
        {
            return Err(Error::Profile);
        }
        let dwell = request.dwell_ms.min(125);
        let own = self.radio.local().ok_or(Error::State)?;
        for &channel in request.channels {
            let permission = self.channel_permission(channel);
            self.authority().invoke(|| ()).map_err(Error::Radio)?;
            permission?;
            Prepared::new(own, channel, request.ssid, 0, channel == 1, request.extra)
                .map_err(Error::Radio)?
                .timing(dwell, request.mandatory)
                .map_err(Error::Radio)?;
        }
        let authority = self.authority();
        let mut attempt = self.attempt();
        let result = authority
            .fence(
                async {
                    let mut observations = Vec::new();
                    for &channel in request.channels {
                        self.scan_drain(environment, *generation, &mut observations)
                            .await?;
                        self.scan_null(true, environment.now_ms())?;
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
                        // Force a real cold receive generation even when an
                        // active request includes the current home channel.
                        // No bound-peer exception is added to submit_probe.
                        let permission = self
                            .radio
                            .cold_scan_channel(channel, channel == self.permission.channel())
                            .await
                            .map_err(Error::Radio)?;
                        *generation = next;
                        let sequence = self.reserve_plain_sequence()?;
                        let probe = Prepared::new(
                            own,
                            channel,
                            request.ssid,
                            sequence,
                            self.radio.ht_enabled(),
                            request.extra,
                        )
                        .map_err(Error::Radio)?;
                        let timing = probe
                            .timing(dwell, request.mandatory)
                            .map_err(Error::Radio)?;
                        self.active_visit(
                            &probe,
                            permission,
                            timing,
                            environment,
                            *generation,
                            &mut observations,
                        )
                        .await?;
                        let next = generation.checked_add(1).ok_or(Error::State)?;
                        // restore_station forces actual MAC/FIFO/USB restart;
                        // both generation advances correspond to real streams.
                        self.radio
                            .restore_station(home, self.permission)
                            .await
                            .map_err(Error::Radio)?;
                        *generation = next;
                        let now = environment.now_ms();
                        if now < self.last_now {
                            return Err(Error::State);
                        }
                        self.last_now = now;
                        self.last_peer = now;
                        self.next_watchdog = now.saturating_add(2000);
                        self.scan_null(false, now)?;
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

    async fn active_visit<E: Environment>(
        &mut self,
        probe: &Prepared,
        permission: power_policy::Permission,
        timing: (u64, u64),
        environment: &E,
        generation: u64,
        observations: &mut Vec<Observation>,
    ) -> Result<(), Error> {
        let (pre, post) = timing;
        let authority = self.radio.authority();
        authority
            .fence(
                async {
                    self.scan_away_listen(pre, environment, generation, observations)
                        .await?;
                    self.radio
                        .enable_transmit(permission)
                        .await
                        .map_err(Error::Radio)?;
                    self.radio.submit_probe(probe).map_err(Error::Radio)?;
                    let until = environment.now_ms().checked_add(1000).ok_or(Error::State)?;
                    let mut delivered = false;
                    for _ in 0..20_000 {
                        // Keep the same native RX stream live during a delayed host
                        // TX completion. No station key/BA receive path runs here.
                        self.scan_away_listen(0, environment, generation, observations)
                            .await?;
                        if let Some(receipt) = self.radio.poll_delivery().map_err(Error::Radio)? {
                            if receipt.native_bytes != probe.bytes().len() {
                                return Err(Error::State);
                            }
                            delivered = true;
                            break;
                        }
                        if environment.now_ms() >= until {
                            return Err(Error::Timeout);
                        }
                        environment.pause().await;
                    }
                    if !delivered {
                        return Err(Error::Timeout);
                    }
                    // Device air consumption remains independent of host delivery.
                    self.scan_away_listen(post, environment, generation, observations)
                        .await?;
                    self.radio.finish_probe().await.map_err(Error::Radio)
                },
                Error::Radio,
            )
            .await
    }
}
