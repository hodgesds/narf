// SPDX-License-Identifier: GPL-2.0-or-later
//! Mounted below prepare::station: AE-only NASR/current-policy MLME seams.
//! No CE/BE firmware, GPIO or power-save interpretation is inherited.
use super::{power_wait, Environment, Error, Hardware, Memory, Port, Prepared};
use crate::rtlwifi::{
    rtl8723ae::{h2c, station_policy::Program},
    station_power::{Base, Grant},
};
use alloc::sync::Arc;

/// `rtl8723e_dm_refresh_rate_adaptive_mask`: LOW high threshold is 60,
/// and a missing bound-peer beacon/probe response forces HIGH/INIT to
/// MIDDLE or MIDDLE/LOW to LOW. The 88EE helper has different behavior.
pub(super) fn next_level(previous: u8, pwdb: i64, beacons: u32) -> u8 {
    if beacons == 0 {
        return if matches!(previous, 2 | 3) { 3 } else { 2 };
    }
    let (high, low) = match previous {
        2 => (55, 20),
        3 => (60, 25),
        _ => (50, 20),
    };
    if pwdb > high {
        1
    } else if pwdb > low {
        2
    } else {
        3
    }
}
impl<I: crate::rtlwifi::firmware_transport::Io, M: Memory> Prepared<I, M> {
    pub(in crate::rtlwifi) fn rtl8723ae_program(
        &self,
    ) -> Result<
        (
            Arc<Program>,
            crate::rtlwifi::rtl8723ae::station_policy::Grant,
        ),
        crate::rtlwifi::prepare::Error,
    > {
        let state = self
            .ae8723
            .as_ref()
            .ok_or(crate::rtlwifi::prepare::Error::State)?;
        Ok((state.program.clone(), state.grant))
    }
    pub(in crate::rtlwifi) fn rtl8723ae_ready(
        &self,
        factory: &crate::rtlwifi::efuse::Factory,
        channel: u8,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<(), crate::rtlwifi::prepare::Error> {
        use crate::rtlwifi::prepare::{Error as Radio, Phase};
        let state = self.ae8723.as_ref().ok_or(Radio::State)?;
        let binding = state.program.prepared();
        if !state.mac_ready
            || !state.live.load(core::sync::atomic::Ordering::Acquire)
            || !matches!(self.phase, Phase::MacConfigured | Phase::Running)
            || state.grant.channel() != channel
            || binding.factory().mac != factory.mac
            || binding.factory().logical != factory.logical
            || state.program.grant_for(domain)? != state.grant
            || !matches!(self.station.calibration.as_ref(),Some(Base::Rtl8723ae(base)) if Arc::ptr_eq(base,&state.program))
        {
            return Err(Radio::State);
        }
        state.program.with_current(|| Ok(()))
    }
    pub(in crate::rtlwifi) fn stage_rtl8723ae_station_program(
        &mut self,
        program: Arc<Program>,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<(), Error> {
        let state = self.ae8723.as_ref().ok_or(Error::State)?;
        if !state.mac_ready || !Arc::ptr_eq(&state.program, &program) {
            return Err(Error::Profile);
        }
        if self.phase != Hardware::MacConfigured
            || self.station.phase != super::Phase::Dormant
            || program.grant_for(domain).map_err(Error::Radio)? != state.grant
        {
            return Err(Error::Profile);
        }
        // This exact source is staged while native station_live is still
        // false; only retained activation can publish the final receipt.
        self.station.calibration = Some(Base::Rtl8723ae(program));
        Ok(())
    }
    pub(super) fn native_station_radio_on(&self) -> Result<(), crate::rtlwifi::prepare::Error> {
        if self.chip == super::super::Chip::Rtl8723ae {
            let version = self
                .ae8723
                .as_ref()
                .ok_or(crate::rtlwifi::prepare::Error::State)?
                .program
                .prepared()
                .adapter()
                .version;
            crate::rtlwifi::rtl8723ae::radio_switch::on(&self.io, version)
        } else if self.chip == super::super::Chip::Rtl8723be {
            // Linux rtl8723be_gpio_radio_on_off_checking: make the switch
            // pin an input (REG_GPIO_IO_SEL_2 0x62 bit 1 clear), then read
            // REG_GPIO_PIN_CTRL_2 (0x60) bit 1; set is RF on. 0x6c bit 31,
            // the fallback below, is the RTL8188EE switch (REG_GPIO_OUTPUT);
            // on this chip 0x6c is a GPIO output register.
            // LINUX-GAP: `rtlphy->polarity_ctl`, which inverts the sense, is
            // not modelled; the default (non-inverted) sense applies.
            let sel = self.io.read8(0x62)?;
            self.io.write8(0x62, sel & !(1 << 1))?;
            if self.io.read8(0x60)? & (1 << 1) == 0 {
                return Err(crate::rtlwifi::prepare::Error::RadioOff);
            }
            Ok(())
        } else {
            crate::rtlwifi::station_control::radio_on(&self.io)
        }
    }
}
impl<I: Port<Buffer = M>, M: Memory> Prepared<I, M> {
    pub(super) async fn install_rtl8723ae_station_rate_mask(
        &mut self,
        rates: u16,
        level: u8,
        environment: &impl Environment,
    ) -> Result<(), Error> {
        if self.packet.width.is_some()
            || (self.station.ht_profile.is_some() && !self.rtl8723ae_ht())
        {
            return Err(Error::Profile);
        }
        let peer = h2c::Peer {
            mode: if self.station.ht_profile.is_some() {
                h2c::WirelessMode::N24
            } else if rates & !0xf == 0 {
                h2c::WirelessMode::B
            } else {
                h2c::WirelessMode::G
            },
            supp_rates: u32::from(rates),
            rx_mask: [
                self.station
                    .ht_profile
                    .map_or(0, |profile| profile.tx_mcs()[0]),
                0,
            ],
            sgi20: self
                .station
                .ht_profile
                .is_some_and(|profile| profile.tx_sgi20()),
            sgi40: false,
        };
        let base = self
            .station
            .calibration
            .as_ref()
            .ok_or(Error::State)?
            .clone();
        let grant = self.station_grant().ok_or(Error::State)?;
        if !matches!(grant, Grant::Rtl8723ae(_)) {
            return Err(Error::Profile);
        }
        power_wait(
            base,
            None,
            None,
            None,
            None,
            grant,
            environment,
            self.install_rtl8723ae_rate_mask(peer, level),
        )
        .await?;
        self.check_station_policy(environment)
    }
    pub(super) async fn rtl8723ae_watchdog(
        &mut self,
        environment: &impl Environment,
    ) -> Result<bool, Error> {
        if !self.station_linked()
            || self.leisure()
            || !self.transmit_ready()
            || self.rate_mask().is_none()
            || !self.station.ra.due(environment.now_ms())
        {
            return Ok(false);
        }
        self.check_station_policy(environment)?;
        self.ae8723_service_c2h()?;
        let beacons = self.packet.ae8723.beacons;
        let level = next_level(self.station.ra.level(), self.station.ra.smoothed(), beacons);
        let changed = level != self.station.ra.level();
        if changed {
            let (rates, _) = self
                .station
                .plan
                .as_ref()
                .ok_or(Error::State)?
                .legacy_rates();
            self.install_rtl8723ae_station_rate_mask(rates, level, environment)
                .await?;
            self.station.ra.commit(level);
        }
        let base = self
            .station
            .calibration
            .as_ref()
            .ok_or(Error::State)?
            .clone();
        let grant = self.station_grant().ok_or(Error::State)?;
        let pwdb = self.station.ra.smoothed();
        let now = environment.now_ms();
        power_wait(
            base,
            None,
            None,
            None,
            None,
            grant,
            environment,
            self.ae8723_coex_watchdog(pwdb, now),
        )
        .await?;
        self.packet.ae8723.beacons = 0;
        self.check_station_policy(environment)?;
        if self.phase != Hardware::Running {
            return Err(Error::State);
        }
        Ok(changed)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
fn smoke_ae_native_rate_watchdog_has_own_thresholds_and_beacon_fallback(
) -> narf_kernel_test::TestResult {
    use narf_kernel_test::{kt_assert_eq, TestResult};
    for (previous, pwdb, beacons, want) in [
        (3, 60, 1, 2),
        (3, 61, 1, 1),
        (3, 25, 1, 3),
        (3, 26, 1, 2),
        (2, 55, 1, 2),
        (2, 56, 1, 1),
        (1, 50, 1, 2),
        (1, 20, 1, 3),
        (0, 100, 0, 2),
        (1, 100, 0, 2),
        (2, 100, 0, 3),
        (3, 100, 0, 3),
    ] {
        kt_assert_eq!(next_level(previous, pwdb, beacons), want);
    }
    TestResult::Pass
}
#[cfg(any(test, feature = "kernel-test"))]
narf_kernel_test::kernel_test_in! {"drivers/wireless/rtlwifi/rtl8723ae",smoke_ae_native_rate_watchdog_has_own_thresholds_and_beacon_fallback}
