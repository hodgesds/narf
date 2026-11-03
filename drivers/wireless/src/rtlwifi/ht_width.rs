// SPDX-License-Identifier: GPL-2.0-or-later
//! Source-style same-primary20/40 transitions. No DMA resource is reclaimed.
use super::super::super::ht::{self, Geometry};
use super::*;
impl<I: Port<Buffer = M>, M: Memory> Prepared<I, M> {
    pub(super) fn offered_width(
        width: association::phy::Width,
        operation: &association::phy::HtOperation,
    ) -> Result<Option<Geometry>, Error> {
        match width {
            association::phy::Width::Twenty => Ok(None),
            association::phy::Width::Forty => {
                let (primary, secondary) = (
                    operation.primary(),
                    operation.secondary().ok_or(Error::Profile)?,
                );
                // 5 GHz pairs only ever reach the RTL8821AE profile, whose
                // owner is the only one granted a 5 GHz channel.
                if primary >= 36 {
                    Geometry::new_5g(primary, secondary)
                } else {
                    Geometry::new(primary, secondary)
                }
                .map(Some)
                .map_err(Error::Radio)
            }
            _ => Err(Error::Profile),
        }
    }
    /// RTL8821AE: [`Self::offered_width`], with an 80 MHz selection
    /// reduced to its primary HT40 pair (`mac->cur_40_prime_sc` inside the
    /// 80 MHz channel; the HT Operation secondary must name it).
    pub(super) fn rtl8821ae_offered_width(
        width: association::phy::Width,
        operation: &association::phy::HtOperation,
    ) -> Result<Option<Geometry>, Error> {
        match width {
            association::phy::Width::Eighty => {
                Self::offered_width(association::phy::Width::Forty, operation)
            }
            width => Self::offered_width(width, operation),
        }
    }
    /// RTL8821AE: the AP's offered VHT80 channel with its `NAPC` 80 MHz
    /// permission, when the envelope measures it, current host policy
    /// admits it, its 80 MHz block is the AP's (VHT Operation center) and
    /// it admits every AC_5G RA-mask rate (`rtl8821ae::vht::admitted`).
    /// `None` keeps the HT20/40 profile.
    pub(super) fn rtl8821ae_vht80(
        &self,
        candidate: &Candidate,
        environment: &impl Environment,
    ) -> Result<Option<super::super::super::rtl8821ae::envelope::Permission>, Error> {
        use super::super::super::rtl8821ae::envelope::{Band, Operating, Width};
        let Some(base) = self
            .station
            .calibration
            .as_ref()
            .and_then(|base| base.rtl8821ae())
        else {
            return Ok(None);
        };
        let offer = association::phy::Offer::from_elements(
            super::super::super::rtl8821ae::vht::local(),
            &candidate.bss.information_elements,
            candidate.bss.channel,
        )
        .map_err(Error::Management)?;
        let Some(offer) = offer else {
            return Ok(None);
        };
        if offer.width() != association::phy::Width::Eighty || offer.vht().is_none() {
            return Ok(None);
        }
        let op = Operating {
            band: Band::B5g,
            width: Width::W80,
            channel: offer.ht().operation().primary(),
        };
        if op.channel < 36 || op.wide_channel() != Some(offer.center_channel()) {
            return Ok(None);
        }
        Ok(base
            .permission_for(&environment.domain()?, op)
            .ok()
            .filter(super::super::super::rtl8821ae::vht::admitted))
    }
    pub(super) fn local_ht_for(
        &self,
        candidate: &Candidate,
    ) -> Result<association::phy::LocalPhy, Error> {
        if self.station.wide_profiles.is_empty() {
            return Ok(ht::local());
        }
        let offer = association::phy::Offer::from_elements(
            ht::local_wide(),
            &candidate.bss.information_elements,
            candidate.bss.channel,
        )
        .map_err(Error::Management)?;
        if let Some(offer) = offer {
            if let Ok(Some(g)) = Self::offered_width(offer.width(), offer.ht().operation()) {
                if self
                    .station
                    .wide_profiles
                    .iter()
                    .any(|q| q.geometry() == Some(g))
                {
                    return Ok(ht::local_wide());
                }
            }
        }
        Ok(ht::local())
    }
    /// RTL8821AE: the AP's offered HT40 geometry with its `NAPC` 40 MHz
    /// permission, when the envelope measures it, current host policy
    /// admits it and it admits HT (MCS0-7). `None` keeps the HT20 form.
    pub(super) fn rtl8821ae_wide(
        &self,
        candidate: &Candidate,
        environment: &impl Environment,
    ) -> Result<
        Option<(
            super::super::super::ht::Geometry,
            super::super::super::rtl8821ae::envelope::Permission,
        )>,
        Error,
    > {
        use super::super::super::rtl8821ae::envelope::{Band, Operating, Width};
        let Some(base) = self
            .station
            .calibration
            .as_ref()
            .and_then(|base| base.rtl8821ae())
        else {
            return Ok(None);
        };
        let offer = association::phy::Offer::from_elements(
            super::super::super::rtl8821ae::ht::local(true),
            &candidate.bss.information_elements,
            candidate.bss.channel,
        )
        .map_err(Error::Management)?;
        let Some(offer) = offer else {
            return Ok(None);
        };
        let Ok(Some(g)) = Self::offered_width(offer.width(), offer.ht().operation()) else {
            return Ok(None);
        };
        let op = Operating {
            band: if g.primary() >= 36 {
                Band::B5g
            } else {
                Band::B2g
            },
            width: if g.prime() == 1 {
                Width::W40Above
            } else {
                Width::W40Below
            },
            channel: g.primary(),
        };
        Ok(base
            .permission_for(&environment.domain()?, op)
            .ok()
            .filter(super::super::super::rtl8821ae::ht::admitted)
            .map(|p| (g, p)))
    }
    /// RTL8192EE: the AP's offered HT40 geometry with its `N92E` 40 MHz
    /// permission, when the envelope measures it, current host policy
    /// admits it and it admits HT (MCS0-7). `None` keeps the HT20 form.
    pub(super) fn rtl8192ee_wide(
        &self,
        candidate: &Candidate,
        environment: &impl Environment,
    ) -> Result<
        Option<(
            super::super::super::ht::Geometry,
            super::super::super::rtl8192ee::envelope::Permission,
        )>,
        Error,
    > {
        use super::super::super::rtl8192ee::envelope::{Operating, Width};
        let Some(base) = self
            .station
            .calibration
            .as_ref()
            .and_then(|base| base.rtl8192ee())
        else {
            return Ok(None);
        };
        let two = self
            .rtl8192ee_power
            .is_some_and(|p| super::super::super::rtl8192ee::ht::two_stream(&p));
        let offer = association::phy::Offer::from_elements(
            super::super::super::rtl8192ee::ht::local(true, two),
            &candidate.bss.information_elements,
            candidate.bss.channel,
        )
        .map_err(Error::Management)?;
        let Some(offer) = offer else {
            return Ok(None);
        };
        let Ok(Some(g)) = Self::offered_width(offer.width(), offer.ht().operation()) else {
            return Ok(None);
        };
        if g.primary() >= 36 {
            return Ok(None);
        }
        let op = Operating {
            width: if g.prime() == 1 {
                Width::W40Above
            } else {
                Width::W40Below
            },
            channel: g.primary(),
        };
        Ok(base
            .permission_for(&environment.domain()?, op)
            .ok()
            .filter(super::super::super::rtl8192ee::ht::admitted)
            .map(|p| (g, p)))
    }
    /// RTL8192EE local TX MCS selection (`rtl8192ee::ht::capability`):
    /// MCS8-15 only when the `N92E` permission at 20 MHz on the provisioned
    /// primary and, when a 40 MHz one is offered, that one too admit every
    /// two-stream rate on both paths (Configuring may narrow the
    /// negotiated width to 20 MHz), so mac80211's intersected `rx_mask[1]`
    /// can only name rates the RA mask may install.
    pub(super) fn rtl8192ee_two_stream(
        &self,
        wide: Option<&super::super::super::rtl8192ee::envelope::Permission>,
        environment: &impl Environment,
    ) -> Result<bool, Error> {
        use super::super::super::rtl8192ee::{envelope::Operating, ht::two_stream};
        let Some(base) = self
            .station
            .calibration
            .as_ref()
            .and_then(|base| base.rtl8192ee())
        else {
            return Ok(false);
        };
        let channel = self.rtl8192ee_power.ok_or(Error::State)?.channel();
        let narrow = base
            .permission_for(&environment.domain()?, Operating::twenty(channel))
            .ok();
        Ok(narrow.as_ref().is_some_and(two_stream) && wide.is_none_or(two_stream))
    }
    /// RTL8821AE `rtl_op_config` channel/width change on the running owner
    /// (mac80211 sets the BSS chandef before authentication and narrows it
    /// if the association response does): the permission for the target
    /// operating point (`width` 40 MHz on the provisioned primary, else
    /// 20 MHz) is re-derived from the `NAPC` envelope under current host
    /// policy, then `channel::configure` (`sw_chnl_callback`, TXAGC at the
    /// wide channel, `set_bw_mode_callback`) runs inside that permission's
    /// authority. No frame may be outstanding; the old receive epoch is
    /// retired. A failure leaves the owner failed. `eighty` selects the
    /// 80 MHz VHT channel around `width`'s primary HT40 pair
    /// (`rtl_op_config` `NL80211_CHAN_WIDTH_80`), which needs a VHT80-
    /// admitting permission.
    pub(super) async fn retune_rtl8821ae(
        &mut self,
        width: Option<super::super::super::ht::Geometry>,
        eighty: bool,
        environment: &impl Environment,
    ) -> Result<(), Error> {
        use super::super::super::rtl8821ae::envelope::{Operating, Width};
        let current = self.rtl8821ae_power.ok_or(Error::State)?;
        let channel = current.channel();
        let op = match width {
            Some(g) if eighty && g.primary() == channel => Operating {
                band: current.operating().band,
                width: Width::W80,
                channel,
            },
            _ if eighty => return Err(Error::Profile),
            None => Operating::twenty(channel),
            Some(g) if g.primary() == channel => Operating {
                band: current.operating().band,
                width: if g.prime() == 1 {
                    Width::W40Above
                } else {
                    Width::W40Below
                },
                channel,
            },
            Some(_) => return Err(Error::Profile),
        };
        if current.operating() == op && self.packet.width == width && self.packet.eighty == eighty {
            return Ok(());
        }
        if !self.transmit_ready()
            || self.station.pending.is_some()
            || !matches!(self.station.phase, Phase::Joining | Phase::Configuring)
        {
            return Err(Error::State);
        }
        self.check_station_policy(environment)?;
        let base = self
            .station
            .calibration
            .as_ref()
            .and_then(|base| base.rtl8821ae())
            .ok_or(Error::Profile)?
            .clone();
        let permission = base
            .permission_for(&environment.domain()?, op)
            .map_err(|e| Error::Radio(RadioError::Power(e)))?;
        if width.is_some() && !super::super::super::rtl8821ae::ht::admitted(&permission)
            || eighty && !super::super::super::rtl8821ae::vht::admitted(&permission)
        {
            return Err(Error::Profile);
        }
        let reg_837 = self.rtl8821ae.ok_or(Error::State)?.reg_837;
        self.station.retire_receive();
        self.phase = Hardware::Failed;
        self.rtl8821ae_power = None;
        let io = &self.io;
        super::super::super::station_power::wait_rtl8821ae(base, permission, environment, async {
            io.authority(true, || Ok(()))?;
            super::super::super::rtl8821ae::channel::configure(io, &permission, reg_837).await
        })
        .await?;
        self.rtl8821ae_power = Some(permission);
        self.packet.width = width;
        self.packet.eighty = eighty;
        self.phase = Hardware::Running;
        self.check_station_policy(environment)
    }
    /// `cur_40_prime_sc` of the programmed RTL8192EE operating point (0 at
    /// 20 MHz or without a grant).
    pub(super) fn rtl8192ee_prime_sc(&self) -> u8 {
        self.rtl8192ee_power
            .and_then(|p| p.operating().channel())
            .map_or(0, |c| c.prime_sc)
    }
    /// RTL8192EE `rtl_op_config` channel/width change on the running owner
    /// (mac80211 sets the BSS chandef before authentication and narrows it
    /// if the association response does): the `N92E` permission for the
    /// target operating point (`width` 40 MHz on the provisioned primary,
    /// else 20 MHz) is re-derived under current host policy, then
    /// `Prepared::configure_rtl8192ee_channel` (`sw_chnl` at the wide
    /// channel with the admitted per-path indices, `set_bw_mode`) runs
    /// inside that permission's authority. No frame may be outstanding; the
    /// old receive epoch is retired. A failure leaves the owner failed.
    pub(super) async fn retune_rtl8192ee(
        &mut self,
        width: Option<super::super::super::ht::Geometry>,
        environment: &impl Environment,
    ) -> Result<(), Error> {
        use super::super::super::rtl8192ee::envelope::{Operating, Width};
        let current = self.rtl8192ee_power.ok_or(Error::State)?;
        let channel = current.channel();
        let op = match width {
            None => Operating::twenty(channel),
            Some(g) if g.primary() == channel => Operating {
                width: if g.prime() == 1 {
                    Width::W40Above
                } else {
                    Width::W40Below
                },
                channel,
            },
            Some(_) => return Err(Error::Profile),
        };
        if current.operating() == op && self.packet.width == width {
            return Ok(());
        }
        if !self.transmit_ready()
            || self.station.pending.is_some()
            || !matches!(self.station.phase, Phase::Joining | Phase::Configuring)
        {
            return Err(Error::State);
        }
        self.check_station_policy(environment)?;
        let base = self
            .station
            .calibration
            .as_ref()
            .and_then(|base| base.rtl8192ee())
            .ok_or(Error::Profile)?
            .clone();
        let permission = base
            .permission_for(&environment.domain()?, op)
            .map_err(|e| Error::Radio(RadioError::Power(e)))?;
        if width.is_some() && !super::super::super::rtl8192ee::ht::admitted(&permission) {
            return Err(Error::Profile);
        }
        self.station.retire_receive();
        let owner = &mut *self;
        super::super::super::station_power::wait_rtl8192ee(base, permission, environment, async {
            owner.io.authority(true, || Ok(()))?;
            owner.configure_rtl8192ee_channel(permission).await
        })
        .await?;
        self.packet.width = width;
        self.check_station_policy(environment)
    }
    pub(super) async fn select_station_width(
        &mut self,
        width: Option<Geometry>,
        environment: &impl Environment,
    ) -> Result<(), Error> {
        let target = if let Some(g) = width {
            self.station
                .wide_profiles
                .iter()
                .find(|q| q.geometry() == Some(g))
                .cloned()
                .ok_or(Error::Profile)?
        } else {
            let Some(q) = self.station.ht.clone() else {
                return Ok(());
            };
            q
        };
        if self.packet.width == width
            && self
                .station
                .ht
                .as_ref()
                .is_some_and(|q| Arc::ptr_eq(q, &target))
        {
            return Ok(());
        }
        if !self.transmit_ready()
            || self.station.pending.is_some()
            || !matches!(self.station.phase, Phase::Joining | Phase::Configuring)
        {
            return Err(Error::State);
        }
        self.check_station_policy(environment)?;
        let base = self.ee_base()?.ok_or(Error::Profile)?;
        let permission = self.permission.ok_or(Error::State)?;
        let gains = target.gains(&environment.domain()?, permission)?;
        if target.geometry().is_none() || width.is_some_and(|g| g.primary() != permission.channel())
        {
            return Err(Error::Profile);
        }
        // Old copied records retain their original epoch. Existing DMA OWN
        // descriptors and buffers remain untouched throughout this transition.
        self.station.retire_receive();
        self.phase = Hardware::Failed;
        let fence = target.clone();
        let protection = self.station.protection.clone();
        let tracking = self.station.tracking.as_ref().map(|s| s.grant.clone());
        let antenna = self.station.antenna.as_ref().map(|s| s.grant.clone());
        let operation = async {
            self.io.authority(true, || Ok(()))?;
            let pause = self.io.read8(0x522)?;
            self.io.write8(0x522, 0xff)?;
            if self.io.read8(0x522)? != 0xff {
                return Err(RadioError::Readback);
            }
            let mut idle = false;
            for _ in 0..101 {
                if self.io.read32(0x5f8)? == 0 {
                    idle = true;
                    break;
                }
                self.io.delay_us(10).await;
            }
            if !idle {
                return Err(RadioError::PacketTimeout);
            }
            let cr = self.io.read8(0x100)?;
            if cr & 0xc0 != 0xc0 {
                return Err(RadioError::State);
            }
            self.io.write8(0x100, cr & !0xc0)?;
            if self.io.read8(0x100)? & 0xc0 != 0 {
                return Err(RadioError::Readback);
            }
            update8(&self.io, 0x603, 4, if width.is_some() { 0 } else { 4 })?;
            for reg in [0x800, 0x900] {
                update32(&self.io, reg, 1, u32::from(width.is_some()))?;
            }
            if let Some(g) = width {
                let prior = self.io.read8(0x442)?;
                self.io.write8(0x442, (prior & 0x90) | (g.prime() << 5))?;
                update32(&self.io, 0xa00, 0x10, u32::from(g.prime() >> 1) << 4)?;
                update32(&self.io, 0xd00, 0xc00, u32::from(g.prime()) << 10)?;
                update32(
                    &self.io,
                    0x818,
                    0xc000000,
                    (if g.prime() == 1 { 2 } else { 1 }) << 26,
                )?;
            }
            let prior = super::super::super::radio::rf_read(&self.io, 0x18)
                .await
                .map_err(RadioError::Radio)?;
            let rf = (prior & !0xfff)
                | width.map_or(u32::from(permission.channel()) | 0xc00, |g| {
                    u32::from(g.center()) | 0x400
                });
            super::super::super::radio::rf_write(&self.io, 0x18, rf)
                .await
                .map_err(RadioError::Radio)?;
            self.io.delay_us(10_000).await;
            if super::super::super::radio::rf_read(&self.io, 0x18)
                .await
                .map_err(RadioError::Radio)?
                != rf
            {
                return Err(RadioError::Readback);
            }
            for (reg, row) in [0xe10, 0xe14].into_iter().zip(gains.chunks_exact(4)) {
                self.io
                    .write32(reg, u32::from_le_bytes(row.try_into().unwrap()))?;
            }
            target.readback_width(&self.io, gains, false, width)?;
            if target.gains(
                &environment.domain().map_err(|_| RadioError::State)?,
                permission,
            )? != gains
            {
                return Err(RadioError::State);
            }
            // No logical key or ordinary DATA exists yet. A copied old40
            // descriptor remains40 and is refused after a20 fallback; old20
            // remains a valid narrow reception on this unchanged primary.
            self.packet.width = width;
            self.station.ht = Some(target.clone());
            self.station.ht_indices = gains;
            self.radio.as_mut().ok_or(RadioError::State)?.channel_rf = rf;
            self.io.write8(0x100, cr)?;
            self.io.write8(0x522, pause)?;
            if self.io.read8(0x100)? != cr || self.io.read8(0x522)? != pause {
                return Err(RadioError::Readback);
            }
            Ok(())
        };
        ht::wait(
            base,
            Some(fence),
            protection,
            tracking,
            antenna,
            permission,
            environment,
            operation,
        )
        .await?;
        self.phase = Hardware::Running;
        self.check_station_policy(environment)
    }
}
fn update8(io: &impl Io, reg: u16, mask: u8, value: u8) -> Result<(), RadioError> {
    let old = io.read8(reg)?;
    io.write8(reg, (old & !mask) | value)?;
    if io.read8(reg)? & mask != value {
        return Err(RadioError::Readback);
    };
    Ok(())
}
fn update32(io: &impl Io, reg: u16, mask: u32, value: u32) -> Result<(), RadioError> {
    let old = io.read32(reg)?;
    io.write32(reg, (old & !mask) | value)?;
    if io.read32(reg)? & mask != value {
        return Err(RadioError::Readback);
    };
    Ok(())
}
