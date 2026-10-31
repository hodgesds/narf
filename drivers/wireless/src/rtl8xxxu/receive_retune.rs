// SPDX-License-Identifier: GPL-2.0-or-later
//! Idle-only channel changes over one retained physical radio/USB claim.
//! RXDMA idle alone does not empty its FIFO: a complete cold NIC restart
//! retires the old receive stream before any new channel label is published.
use super::*;

impl<C: ControlIo, B: PacketIo> Receiver<C, B> {
    pub(in crate::rtl8xxxu) fn permission_for_channel(
        &self,
        channel: u8,
    ) -> Result<super::super::power_policy::Permission, Error> {
        Ok(self
            .wmm
            .as_ref()
            .ok_or(Error::State)?
            .for_channel(channel)?
            .permission())
    }

    pub(in crate::rtl8xxxu) async fn cold_retune(
        &mut self,
        channel: u8,
    ) -> Result<super::super::power_policy::Permission, Error> {
        if self.phase() != Phase::Receiving || self.peer.is_some() {
            return Err(Error::State);
        }
        let base = self.wmm.as_ref().ok_or(Error::State)?;
        let target = base.for_channel(channel)?;
        let permission = target.permission();
        if channel == self.channel() {
            return Ok(permission);
        }
        // The source cold LC/IQK program runs on home channel1. Both that
        // calibration program and the selected operating row must stay valid.
        let home = base.for_channel(1)?;
        let authority = self.authority();
        let ht = if channel == 1 {
            self.home_ht.clone()
        } else {
            None
        };
        let factory = self.firmware.factory().ok_or(Error::State)?;
        let mut attempt = Attempt {
            firmware: self.firmware.clone(),
            armed: true,
        };
        let result = authority
            .fence(
                async {
                    home.fence(
                        target.fence(
                            async {
                                self.quiesce_restart().await?;
                                self.firmware
                                    .restart_stopped()
                                    .await
                                    .map_err(Error::Control)?;
                                // This is a freshly booted firmware session;
                                // old H2C/RA host bookkeeping cannot survive it.
                                self.mailbox = 0;
                                self.ra = None;
                                self.report_time = None;
                                let rx =
                                    self.firmware.read32(0x284).await.map_err(Error::Control)?;
                                self.firmware
                                    .write32(0x284, rx & !(1 << 18))
                                    .await
                                    .map_err(Error::Control)?;
                                if self.firmware.read32(0x284).await.map_err(Error::Control)?
                                    & (1 << 18)
                                    != 0
                                {
                                    return Err(Error::State);
                                }
                                super::super::channel_runtime::initial20(
                                    &self.firmware,
                                    factory,
                                    channel,
                                )
                                .await
                                .map_err(Error::Control)?;
                                // Exact RF readback precedes the new packet geometry.
                                let actual =
                                    super::super::calibration::read_rf(&self.firmware, 0x18)
                                        .await
                                        .map_err(Error::Control)?;
                                if actual & 0xfff != (u32::from(channel) | 0xc00) {
                                    return Err(Error::State);
                                }
                                self.ht = None;
                                self.ht_gains = None;
                                if let Some(grant) = &ht {
                                    let gains = grant.gains()?;
                                    grant.program(&self.firmware, gains).await?;
                                    self.ht_gains = Some(gains);
                                }
                                self.ht = ht;
                                self.wmm = Some(target.clone());
                                self.packets
                                    .retarget_stopped(channel)
                                    .map_err(Error::Packet)?;
                                self.phase = Phase::Stopped;
                                self.start().await
                            },
                            core::convert::identity,
                        ),
                        core::convert::identity,
                    )
                    .await
                },
                core::convert::identity,
            )
            .await;
        attempt.armed = false;
        if result.is_err() {
            self.fail();
        }
        result.map(|()| permission)
    }

    async fn quiesce_restart(&mut self) -> Result<(), Error> {
        self.phase = Phase::Configuring;
        let cr = self.firmware.read16(0x100).await.map_err(Error::Control)?;
        if cr & 0xc0 != 0x80 {
            return Err(Error::State);
        }
        self.firmware
            .write16(0x100, cr & !0xc0)
            .await
            .map_err(Error::Control)?;
        if self.firmware.read16(0x100).await.map_err(Error::Control)? & 0xc0 != 0 {
            return Err(Error::State);
        }
        for reg in [0x6a0, 0x6a4] {
            self.firmware
                .write16(reg, 0)
                .await
                .map_err(Error::Control)?;
            if self.firmware.read16(reg).await.map_err(Error::Control)? != 0 {
                return Err(Error::State);
            }
        }
        self.firmware
            .write8(0x522, 0xff)
            .await
            .map_err(Error::Control)?;
        let rx = self.firmware.read32(0x284).await.map_err(Error::Control)?;
        self.firmware
            .write32(0x284, rx | (1 << 18))
            .await
            .map_err(Error::Control)?;
        let mut idle = false;
        for _ in 0..101 {
            // The old TD is deliberately still posted until the current
            // device-to-host RXDMA completes; copies are discarded as old.
            if self.firmware.read32(0x284).await.map_err(Error::Control)? & (1 << 17) != 0 {
                idle = true;
                break;
            }
            match self.packets.poll_receive() {
                Ok(_) => (),
                Err(packet_transport::Error::Halted) => {
                    self.packets.recover().await.map_err(Error::Packet)?;
                }
                Err(error) => return Err(Error::Packet(error)),
            }
            self.firmware.delay_us(10).await;
        }
        if !idle {
            return Err(Error::Control(ControlError::PowerTimeout));
        }
        self.packets.stop().await.map_err(Error::Packet)?;
        self.phase = Phase::Stopped;
        self.firmware.receive_stopped();
        Ok(())
    }
}
