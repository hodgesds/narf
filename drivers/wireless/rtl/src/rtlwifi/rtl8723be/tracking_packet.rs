// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual BE retained thermal owner; mounted below prepare::packet::be8723.
use super::*;
use crate::rtlwifi::{
    firmware_transport::{Error as Access, Io},
    rtl8723be::{
        channel, iqk,
        phy::{self, Path},
        tracking::{self, Facts, Grant, Snapshot},
    },
};
use alloc::{boxed::Box, sync::Arc};
use core::sync::atomic::Ordering;
/// Every individual hardware access repeats original+new source and PCI
/// invocation and current host policy. Timer waits themselves emit nothing.
struct Qualified<'a, I, E> {
    io: &'a I,
    grant: &'a Grant,
    environment: &'a E,
}
impl<I: Port, E: super::super::super::station::Environment> Qualified<'_, I, E> {
    fn access<T>(&self, operation: impl FnOnce(&I) -> Result<T, Access>) -> Result<T, Access> {
        self.grant
            .with_current(|| {
                if self.environment.preparation_failed()
                    || self
                        .environment
                        .admission()
                        .is_some_and(|a| a.closed.load(Ordering::Acquire))
                {
                    return Err(Error::State);
                }
                let domain = self.environment.domain().map_err(|_| Error::State)?;
                self.grant
                    .permission_for(&domain, self.grant.facts().permission().operating())
                    .map_err(Error::Power)?;
                self.io
                    .authority(true, || operation(self.io).map_err(Error::Access))
            })
            .map_err(|e| match e {
                Error::Access(e) => e,
                _ => Access::Gate,
            })
    }
}
#[async_trait::async_trait]
impl<I: Port, E: super::super::super::station::Environment> Io for Qualified<'_, I, E> {
    fn read8(&self, r: u16) -> Result<u8, Access> {
        self.access(|io| io.read8(r))
    }
    fn read16(&self, r: u16) -> Result<u16, Access> {
        self.access(|io| io.read16(r))
    }
    fn read32(&self, r: u16) -> Result<u32, Access> {
        self.access(|io| io.read32(r))
    }
    fn write8(&self, r: u16, v: u8) -> Result<(), Access> {
        self.access(|io| io.write8(r, v))
    }
    fn write16(&self, r: u16, v: u16) -> Result<(), Access> {
        self.access(|io| io.write16(r, v))
    }
    fn write32(&self, r: u16, v: u32) -> Result<(), Access> {
        self.access(|io| io.write32(r, v))
    }
    fn write_bytes(&self, r: u16, v: &[u8]) -> Result<(), Access> {
        self.access(|io| io.write_bytes(r, v))
    }
    async fn delay_us(&self, us: u64) {
        self.io.delay_us(us).await;
    }
}
impl<I: Port<Buffer = M>, M: Memory> Prepared<I, M> {
    /// Read-only admission facts under the original NAPC and actual PCI source.
    /// Caller retains the same owner and current policy through installation.
    pub(crate) fn rtl8723be_tracking_facts(
        &self,
        base: &tracking::BaseCalibration,
    ) -> Result<Facts, Error> {
        if !self.rtl8723be()
            || !matches!(self.phase, Phase::MacConfigured | Phase::Running)
            || self.packet.be8723.tracking.is_some()
        {
            return Err(Error::State);
        }
        let (identity, radio) = self.rtl8723be.as_deref().ok_or(Error::State)?;
        base.with_current(|| {
            self.io.authority(self.phase == Phase::Running, || {
                Facts::capture(
                    *identity,
                    radio,
                    self.rtl8723be_power.ok_or(Error::State)?,
                    &self.io,
                )
            })
        })
    }
    /// Install before a new packet-publication epoch; root replaces the station
    /// base with this exact joint grant before any further frame can be emitted.
    pub(crate) fn rtl8723be_install_tracking(&mut self, grant: Arc<Grant>) -> Result<(), Error> {
        if !self.rtl8723be()
            || !matches!(self.phase, Phase::MacConfigured | Phase::Running)
            || self.packet.pending.is_some()
            || self.packet.leisure
            || self.packet.be8723.tracking.is_some()
            || self.rtl8723be_power != Some(grant.facts().permission())
        {
            return Err(Error::State);
        }
        grant.with_current(|| {
            self.io.authority(self.phase == Phase::Running, || {
                if Snapshot::read(&self.io)? != grant.facts().original() {
                    return Err(Error::Readback);
                }
                grant.facts().check_txagc(&self.io)?;
                if self.phase == Phase::Running && self.io.read32(0x5f8)? != 0 {
                    return Err(Error::PacketTimeout);
                }
                Ok(())
            })
        })?;
        self.packet.be8723.tracking = Some(tracking::State::new(grant));
        Ok(())
    }
    /// Full source watchdog with mandatory joint-authority thermal slot.
    pub(crate) async fn rtl8723be_dm_watchdog_qualified(
        &mut self,
        pwdb: i64,
        now: u64,
        environment: &impl super::super::super::station::Environment,
    ) -> Result<bool, Error> {
        if !self.rtl8723be() {
            return Err(Error::State);
        }
        let refreshed = self.be8723_dm_watchdog_head(pwdb).await?;
        if !self.packet.leisure {
            self.be8723_tracking_step(now, environment).await?;
        }
        self.be8723_dm_watchdog_tail(pwdb, now).await?;
        Ok(refreshed)
    }
    async fn be8723_tracking_step(
        &mut self,
        now: u64,
        environment: &impl super::super::super::station::Environment,
    ) -> Result<bool, Error> {
        let Some(state) = self.packet.be8723.tracking.as_ref() else {
            return Ok(false);
        };
        if state.uncertain {
            return Err(Error::State);
        }
        if !state.due(now)
            || self.packet.be8723.link.is_none()
            || self.packet.leisure
            || self.packet.pending.is_some()
        {
            return Ok(false);
        }
        let grant = state.grant.clone();
        let expected = state.expected;
        let mut history = state.history;
        let mut matrix = state.matrix;
        self.phase = Phase::Failed;
        self.packet
            .be8723
            .tracking
            .as_mut()
            .ok_or(Error::State)?
            .uncertain = true;
        let io = Qualified {
            io: &self.io,
            grant: &grant,
            environment,
        };
        expected.check(&io)?;
        grant.facts().check_txagc(&io)?;
        if !history.trigger {
            tracking::source::trigger(&io).await?;
            history.trigger = true;
        } else {
            let raw = tracking::source::sample(&io).await?;
            history.trigger = false;
            if let Some(update) = history.observe(raw, grant.facts().thermal()) {
                if update.lck || update.write || update.iqk {
                    let (cr, pause, rf) = pause(&io, grant.facts().expected_rf()).await?;
                    if update.lck {
                        channel::lc_calibrate(&io).await?;
                        io.write8(0x522, 0xff)?;
                    }
                    if update.write {
                        tracking::source::program(&io, update, matrix)?;
                        history.written(update);
                    }
                    if update.iqk {
                        let outcome = iqk::calibrate(&io).await?;
                        if let Some(new) = outcome.matrix {
                            matrix = new;
                        }
                        // Keep the source's new calibration in the retained radio;
                        // original Facts/IQK backups remain immutable in the grant.
                        self.rtl8723be.as_deref_mut().ok_or(Error::State)?.1.iqk = Some(outcome);
                        history.calibrated(update);
                        io.write8(0x522, 0xff)?;
                    }
                    // LCK's source constant RF18 is a calibration state, not
                    // the admitted channel/width. Restore the actual old RF
                    // program before ordinary MAC gates can reopen.
                    phy::set_rf(&io, Path::A, 0x18, phy::RFREG_OFFSET_MASK, rf).await?;
                    if phy::get_rf(&io, Path::A, 0x18, phy::RFREG_OFFSET_MASK).await? != rf {
                        return Err(Error::Readback);
                    }
                    grant.facts().check_txagc(&io)?;
                    let new = Snapshot::read(&io)?;
                    resume(&io, cr, pause)?;
                    self.packet
                        .be8723
                        .tracking
                        .as_mut()
                        .ok_or(Error::State)?
                        .expected = new;
                }
            }
        }
        // Recheck even if no subsequent MMIO followed a delayed source stage.
        io.access(|_| Ok(())).map_err(Error::Access)?;
        let state = self.packet.be8723.tracking.as_mut().ok_or(Error::State)?;
        state.history = history;
        state.matrix = matrix;
        state.last = Some(now);
        state.uncertain = false;
        self.phase = Phase::Running;
        Ok(true)
    }
    /// Deliberate lifecycle restoration under the OLD current joint grant.
    /// The grant remains installed afterward; only complete card rebuild may
    /// discard it. Failure/cancellation leaves all backups and DMA retained.
    pub(crate) async fn rtl8723be_restore_tracking(
        &mut self,
        environment: &impl super::super::super::station::Environment,
    ) -> Result<(), Error> {
        let Some(state) = self.packet.be8723.tracking.as_ref() else {
            return Ok(());
        };
        if state.uncertain
            || self.phase != Phase::Running
            || self.packet.pending.is_some()
            || self.packet.leisure
        {
            return Err(Error::State);
        }
        let grant = state.grant.clone();
        let expected = state.expected;
        self.phase = Phase::Failed;
        self.packet
            .be8723
            .tracking
            .as_mut()
            .ok_or(Error::State)?
            .uncertain = true;
        let io = Qualified {
            io: &self.io,
            grant: &grant,
            environment,
        };
        expected.check(&io)?;
        let (cr, pause, _rf) = pause(&io, grant.facts().expected_rf()).await?;
        grant.facts().original().restore(&io)?;
        grant.facts().check_txagc(&io)?;
        resume(&io, cr, pause)?;
        let state = self.packet.be8723.tracking.as_mut().ok_or(Error::State)?;
        state.expected = grant.facts().original();
        state.history = tracking::source::History::default();
        state.matrix = grant.facts().matrix();
        state.last = None;
        state.uncertain = false;
        self.packet.be8723.dm = None;
        self.rtl8723be.as_deref_mut().ok_or(Error::State)?.1.iqk = grant.facts().original_report();
        self.phase = Phase::Running;
        Ok(())
    }
}
async fn pause(io: &impl Io, expected_rf: u32) -> Result<(u8, u8, u32), Error> {
    if io.read8(0xd03)? & 0x70 != 0 {
        return Err(Error::State);
    }
    let saved = io.read8(0x522)?;
    io.write8(0x522, 0xff)?;
    if io.read8(0x522)? != 0xff {
        return Err(Error::Readback);
    }
    let mut idle = false;
    for _ in 0..101 {
        let value = io.read32(0x5f8)?;
        if value == u32::MAX {
            return Err(Error::Access(Access::Gone));
        }
        if value == 0 {
            idle = true;
            break;
        }
        io.delay_us(10).await;
    }
    if !idle {
        return Err(Error::PacketTimeout);
    }
    let cr = io.read8(0x100)?;
    if cr & 0xc0 != 0xc0 {
        return Err(Error::State);
    }
    io.write8(0x100, cr & !0xc0)?;
    if io.read8(0x100)? & 0xc0 != 0 {
        return Err(Error::Readback);
    }
    let rf = phy::get_rf(io, Path::A, 0x18, phy::RFREG_OFFSET_MASK).await?;
    if rf != expected_rf {
        return Err(Error::Readback);
    }
    Ok((cr, saved, rf))
}
fn resume(io: &impl Io, cr: u8, pause: u8) -> Result<(), Error> {
    if io.read8(0x522)? != 0xff || io.read8(0x100)? & 0xc0 != 0 {
        return Err(Error::Readback);
    }
    io.write8(0x100, cr)?;
    io.write8(0x522, pause)?;
    if io.read8(0x100)? != cr || io.read8(0x522)? != pause {
        return Err(Error::Readback);
    }
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "tracking_packet_tests.rs"]
pub(crate) mod tests;
