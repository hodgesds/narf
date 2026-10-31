// SPDX-License-Identifier: GPL-2.0-or-later
//! Private prepared-probe publication over the current idle radio profile.
use super::*;

impl<C: ControlIo, B: PacketIo> Receiver<C, B> {
    pub(in crate::rtl8xxxu) fn submit_probe(
        &mut self,
        probe: &super::super::probe_runtime::Prepared,
    ) -> Result<(), Error> {
        self.current_wmm()?;
        if self.phase() != Phase::Active
            || self.peer.is_some()
            || !probe.matches(
                self.local().ok_or(Error::State)?,
                self.channel(),
                self.ht_enabled(),
            )
        {
            return Err(Error::State);
        }
        let result = self
            .authority()
            .invoke(|| self.packets.submit_probe(probe))?;
        if self.packets.is_failed() {
            self.fail();
        }
        result.map_err(Error::Packet)
    }
    pub(in crate::rtl8xxxu) async fn finish_probe(&mut self) -> Result<(), Error> {
        if self.phase() != Phase::Active || self.peer.is_some() || self.packets.transmit_pending() {
            return Err(Error::State);
        }
        let authority = self.authority();
        let mut attempt = Attempt {
            firmware: self.firmware.clone(),
            armed: true,
        };
        let result = authority
            .fence(
                async {
                    // Linux 8188e.c::rtl8188eu_active_to_lps: pause queues,
                    // then observe the actual32-bit SCH_TX_CMD terminal before
                    // closing MAC TX. Host bulk delivery is not this state.
                    let pause = self.firmware.read8(0x522).await.map_err(Error::Control)?;
                    self.firmware
                        .write8(0x522, 0xff)
                        .await
                        .map_err(Error::Control)?;
                    if self.firmware.read8(0x522).await.map_err(Error::Control)? != 0xff {
                        return Err(Error::State);
                    }
                    self.firmware.wait_tx_idle().await.map_err(Error::Control)?;
                    let cr = self.firmware.read16(0x100).await.map_err(Error::Control)?;
                    if cr & 0xc0 != 0xc0 {
                        return Err(Error::State);
                    }
                    self.firmware
                        .write16(0x100, cr & !0x40)
                        .await
                        .map_err(Error::Control)?;
                    if self.firmware.read16(0x100).await.map_err(Error::Control)? & 0xc0 != 0x80 {
                        return Err(Error::State);
                    }
                    self.firmware
                        .write8(0x522, pause)
                        .await
                        .map_err(Error::Control)?;
                    if self.firmware.read8(0x522).await.map_err(Error::Control)? != pause {
                        return Err(Error::State);
                    }
                    // The same physical RX stream stays posted and labelled. This
                    // closes TX admission, not a claim of on-air broadcast ACK or
                    // empty device FIFO; a later retune still needs cold MAC-off.
                    self.phase = Phase::Receiving;
                    Ok(())
                },
                core::convert::identity,
            )
            .await;
        attempt.armed = false;
        if result.is_err() {
            self.fail();
        }
        result
    }
}
