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
            association::phy::Width::Forty => Geometry::new(
                operation.primary(),
                operation.secondary().ok_or(Error::Profile)?,
            )
            .map(Some)
            .map_err(Error::Radio),
            _ => Err(Error::Profile),
        }
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
        let base = self
            .station
            .calibration
            .as_ref()
            .ok_or(Error::State)?
            .clone();
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
