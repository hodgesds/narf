// SPDX-License-Identifier: GPL-2.0-or-later
//! Idle software scan over the same qualified native receive and TX owners.
use super::super::probe_runtime::Prepared;
use super::*;

impl<C: ControlIo, B: packet_transport::Io, E: Environment> Service<C, B, E> {
    pub(in crate::rtl8xxxu) async fn active_scan(
        &mut self,
        channels: &[u8],
        dwell_ms: u64,
        mandatory: bool,
        ssid: &[u8],
        extra: &[u8],
    ) -> Result<(), Error> {
        if self.phase() != Phase::Passive || channels.is_empty() || !(1..=1024).contains(&dwell_ms)
        {
            return Err(Error::State);
        }
        self.check_current()?;
        for &channel in channels {
            let permission = self.channel_permission(channel);
            self.check_current()?;
            permission?;
            // Include the largest possible current profile in pure timing
            // admission, before any stop or RF write. HT is still optional
            // and actual publication uses only the installed grant.
            Prepared::new(self.own, channel, ssid, 0, channel == 1, extra)
                .map_err(Error::Radio)?
                .timing(dwell_ms, mandatory)
                .map_err(Error::Radio)?;
        }
        let home = self.channel()?;
        let mut attempt = Attempt {
            failed: self.failed.clone(),
            armed: true,
        };
        let result = async {
            for &channel in channels {
                self.select_channel(channel).await?;
                self.probe_current(ssid, extra, dwell_ms, mandatory).await?;
            }
            self.select_channel(home).await?;
            self.check_current()?;
            Ok(())
        }
        .await;
        attempt.armed = false;
        if result.is_err() {
            self.fail();
        }
        result
    }

    pub(super) async fn probe_current(
        &mut self,
        ssid: &[u8],
        extra: &[u8],
        dwell_ms: u64,
        mandatory: bool,
    ) -> Result<(), Error> {
        if self.phase() != Phase::Passive {
            return Err(Error::State);
        }
        self.check_current()?;
        let probe = Prepared::new(
            self.own,
            self.channel()?,
            ssid,
            self.probe_sequence,
            self.radio.as_ref().is_some_and(Receiver::ht_enabled),
            extra,
        )
        .map_err(Error::Radio)?;
        let (pre_ms, post_ms) = probe.timing(dwell_ms, mandatory).map_err(Error::Radio)?;
        let authority = self.current()?;
        let mut attempt = Attempt {
            failed: self.failed.clone(),
            armed: true,
        };
        let result = authority
            .fence(
                async {
                    self.probe_listen(pre_ms).await?;
                    self.probing = true;
                    self.radio
                        .as_mut()
                        .ok_or(Error::State)?
                        .enable_transmit(self.permission)
                        .await
                        .map_err(Error::Radio)?;
                    self.radio
                        .as_mut()
                        .ok_or(Error::State)?
                        .submit_probe(&probe)
                        .map_err(Error::Radio)?;
                    self.probe_sequence = (self.probe_sequence + 1) & 4095;
                    let deadline = self.now()?.checked_add(1000).ok_or(Error::State)?;
                    let mut delivered = false;
                    for _ in 0..20_000 {
                        self.poll()?;
                        if let Some(receipt) = self
                            .radio
                            .as_mut()
                            .ok_or(Error::State)?
                            .poll_delivery()
                            .map_err(Error::Radio)?
                        {
                            if receipt.native_bytes != probe.bytes().len() {
                                return Err(Error::State);
                            }
                            delivered = true;
                            break;
                        }
                        if self.now()? >= deadline {
                            return Err(Error::State);
                        }
                        self.environment.pause().await;
                    }
                    if !delivered {
                        return Err(Error::State);
                    }
                    // Host USB completion only proves acceptance by the NIC.
                    // Keep native TX enabled for the source active response
                    // window; the device scheduler receipt follows that dwell.
                    self.probe_listen(post_ms).await?;
                    self.radio
                        .as_mut()
                        .ok_or(Error::State)?
                        .finish_probe()
                        .await
                        .map_err(Error::Radio)?;
                    self.probing = false;
                    self.check_current()?;
                    Ok(())
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
    async fn probe_listen(&mut self, ms: u64) -> Result<(), Error> {
        let until = self.now()?.checked_add(ms).ok_or(Error::State)?;
        for _ in 0..20_000 {
            self.poll()?;
            if self.now()? >= until {
                return Ok(());
            }
            self.environment.pause().await;
        }
        Err(Error::State)
    }
}
