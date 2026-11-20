// SPDX-License-Identifier: GPL-2.0-or-later
//! Physical associated-scan suspension. The logical station and software
//! keys/BA sessions stay in Station; this unit restores the same native owner.
use super::*;

pub(in crate::rtl8xxxu) struct ScanConfig {
    pub peer: [u8; 6],
    pub aid: u16,
    pub short_slot: bool,
    pub edca: Option<narf_wireless::wmm::Parameters>,
    pub ht: bool,
    pub ampdu: Option<(u8, u8)>,
    pub tx_ampdu: Option<(u8, u8)>,
}
pub(in crate::rtl8xxxu) struct ScanHome {
    channel: u8,
    profile_ht: bool,
    wide: Option<super::super::ht_runtime::WidePlan>,
    config: ScanConfig,
    ra: Option<super::super::rate_adaptation::RateAdaptation>,
    report_time: Option<u16>,
}
impl<C: ControlIo, B: PacketIo> Receiver<C, B> {
    pub(in crate::rtl8xxxu) fn submit_null(
        &mut self,
        null: &super::super::ps_null::Prepared,
    ) -> Result<(), Error> {
        self.current_wmm()?;
        if self.phase() != Phase::Active
            || !null.matches(
                self.local().ok_or(Error::State)?,
                self.peer.ok_or(Error::State)?,
                self.packets.qos,
            )
        {
            return Err(Error::State);
        }
        let result = self.authority().invoke(|| self.packets.submit_null(null))?;
        if self.packets.is_failed() {
            self.fail();
        }
        result.map_err(Error::Packet)
    }

    pub(in crate::rtl8xxxu) async fn suspend_station(
        &mut self,
        config: ScanConfig,
    ) -> Result<ScanHome, Error> {
        if self.phase() != Phase::Active
            || self.peer != Some(config.peer)
            || self.packets.transmit_pending()
            || config.ht != self.packets.ht
            || config.edca.is_some() != self.packets.qos
        {
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
                    // After the offchannel.c no-.flush grace, use the chip's
                    // active_to_lps scheduler boundary before closing TX.
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
                    // Detach only hardware peer/report bookkeeping after TX
                    // closed. The subsequent cold retune still must retire
                    // RXDMA, both USB receipts and the actual MAC/FIFO state.
                    self.peer = None;
                    self.phase = Phase::Receiving;
                    Ok(ScanHome {
                        channel: self.channel(),
                        profile_ht: self.ht_enabled(),
                        wide: self.wide.as_ref().map(|program| program.plan()),
                        config,
                        ra: self.ra.take(),
                        report_time: self.report_time.take(),
                    })
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

    /// The response may narrow an offered40MHz link to20MHz. Preserve the
    /// same logical authenticated peer while actually retiring the old native
    /// stream and restoring its selected program before keys/data can open.
    pub(in crate::rtl8xxxu) async fn reconcile_station_geometry(
        &mut self,
        geometry: Option<super::super::ht_runtime::Geometry>,
        config: ScanConfig,
        permission: super::super::power_policy::Permission,
    ) -> Result<(), Error> {
        if geometry.is_none()
            && self
                .wide
                .as_ref()
                .is_some_and(|p| p.mode() == super::super::ht_runtime::WideMode::Forty)
        {
            let mut home = self.suspend_station(config).await?;
            home.wide = Some(home.wide.as_ref().ok_or(Error::State)?.narrow());
            self.restore_station(home, permission).await
        } else {
            self.confirm_station_geometry(geometry)
        }
    }
    pub(in crate::rtl8xxxu) async fn restore_station(
        &mut self,
        home: ScanHome,
        permission: super::super::power_policy::Permission,
    ) -> Result<(), Error> {
        if self.peer.is_some() || permission.channel() != home.channel {
            return Err(Error::State);
        }
        let restored = if let Some(plan) = home.wide {
            self.cold_wide_plan(plan).await?
        } else {
            self.cold_scan_channel(home.channel, home.profile_ht)
                .await?
        };
        if restored != permission {
            return Err(Error::State);
        }
        self.enable_transmit(permission).await?;
        self.prepare_station(home.config.peer, home.config.short_slot)
            .await?;
        if let Some(edca) = home.config.edca {
            self.configure_wmm_phy(edca, home.config.short_slot, home.config.ht)
                .await?;
        }
        self.association(home.config.aid, true).await?;
        if let Some((factor, density)) = home.config.ampdu {
            self.configure_ampdu(factor, density).await?;
        }
        self.set_ampdu_tx(home.config.tx_ampdu);
        self.ra = home.ra;
        // The firmware restart reset this register; reprogram the retained
        // host RA interval rather than pretending its hardware survived.
        self.report_time = home
            .report_time
            .or_else(|| self.ra.as_ref().map(|ra| ra.rpt_time));
        self.apply_report_time().await
    }
}
