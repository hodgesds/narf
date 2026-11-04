// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2008-2011 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
//! AR9280 initial calibration for one 20 MHz channel in either band: the
//! `AR_SREV_9280_20_OR_LATER` branch of `ar9002_calib.c::ar9002_hw_init_cal`
//! below AR9287 1.1 (`AR_PHY_ADC_CTL_OFF_PWDADC` cleared around the
//! `FLTR_CAL` AGC offset calibration; no CLC, no PA calibration — those are
//! AR9285/AR9271 only), `calib.c::ath9k_hw_loadnf`/`_start_nfcal`/`_getnf`
//! with the per-band AR9280 noise-floor limits, and the single-sample
//! (`ar9002_hw_init_cal_settings`: `iq_cal_single_sample` from 9280 2.0)
//! per-chain IQ mismatch calibration. ADC gain and ADC DC are in
//! `supp_cals` but `ar9002_hw_is_cal_supported` runs them on HT40 channels
//! only, so neither runs on this 20 MHz owner. `ar9280_hw_olc_temp_compensation`
//! is `OLC_FOR_AR9280_20_LATER` (open-loop maps), which this closed-loop
//! port refuses, so the periodic owner never runs it.
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use super::{
    ar9287::{self, Limits},
    read, write, Attempt, Io, Permission, State,
};
use crate::ath9k::{
    chips::MAP_DEF,
    identity::{BringUpError, Identity},
    pcie_pm,
    phy::{ar9280::power, Tune},
};

/// New-format `AR_SREV` version of AR9280 (`AR_SREV_VERSION_9280`).
pub(in crate::ath9k) const VERSION: u32 = 0x80;
/// `AR_PHY_CCA_{NOM,MIN_GOOD,MAX_GOOD}_VAL_9280_2GHZ`.
pub(in crate::ath9k) const LIMITS_2GHZ: Limits = Limits {
    nominal: -112,
    min: -127,
    max: -97,
};
/// `AR_PHY_CCA_{NOM,MIN_GOOD,MAX_GOOD}_VAL_9280_5GHZ`.
pub(in crate::ath9k) const LIMITS_5GHZ: Limits = Limits {
    nominal: -112,
    min: -122,
    max: -102,
};

/// `ath9k_hw_get_nf_limits` for the tune's band.
pub(in crate::ath9k) fn limits(tune: Tune) -> Limits {
    if tune.is_5ghz() {
        LIMITS_5GHZ
    } else {
        LIMITS_2GHZ
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub country: [u8; 2],
    pub frequency_mhz: u16,
    pub five_ghz: bool,
    pub max_power_half_dbm: u8,
    pub rx_chainmask: u8,
    /// Per-chain `(iCoff, qCoff)` for chains `0..popcount(rx_chainmask)`.
    pub iq: [Option<(u8, i8)>; 2],
    /// `ar9002_hw_do_getnf` readings before and after `ath9k_hw_nf_sanitize`.
    pub measured_noise_dbm: [Option<i16>; 2],
    pub noise_dbm: [Option<i16>; 2],
}

#[derive(Debug)]
pub(in crate::ath9k) struct Calibration {
    state: State,
    report: Option<Report>,
}
impl Default for Calibration {
    fn default() -> Self {
        Self {
            state: State::New,
            report: None,
        }
    }
}
impl Calibration {
    pub fn state(&self) -> State {
        self.state
    }
    pub fn report(&self) -> Option<Report> {
        self.report
    }
    /// `aspm` is Linux's `ah->aspm_enabled`: only a PCIe part (`0x002a`,
    /// `is_pciexpress`) whose upstream link has ASPM enabled
    /// (`pci.c::ath_pci_aspm_init`) gets the SerDes/workaround programming;
    /// the PCI part (`0x0029`) gets none (`ath9k_hw_disablepcie` is
    /// AR5416-only).
    ///
    /// # Safety
    /// Exclusive identified AR9280 after `phy::ar9280::prepare` for `tune`
    /// at the permission's frequency. PCI BME off, no published packet DMA,
    /// MAC/TX/IRQ parked. Owner and exact factory map survive cancellation;
    /// a new attempt requires an independently proved complete reset.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::ath9k) async unsafe fn run(
        &mut self,
        io: &mut impl Io,
        identity: &Identity,
        image: &[u8],
        tune: Tune,
        rx_chainmask: u8,
        aspm: bool,
        permission: Permission,
    ) -> Result<Report, BringUpError> {
        if self.state != State::New {
            return Err(BringUpError::BadState);
        }
        // Two-chain silicon reading the three-chain def map.
        if image.len() != MAP_DEF.bytes()
            || !(1..=3).contains(&rx_chainmask)
            || rx_chainmask & !identity.rx_chainmask != 0
        {
            return Err(BringUpError::BadIdentity);
        }
        if tune.is_wide() || tune.center() != permission.frequency {
            return Err(BringUpError::Policy);
        }
        if read(io, 0x981c)? & 1 != 0
            || read(io, 8)? & 4 != 0
            || read(io, 0x840)? & 0x3ff != 0
            || read(io, 0x24)? & 1 != 0
            || read(io, 0x8048)? & 0x02000020 != 0x02000020
            || read(io, 0x9860)? & 3 != 0
            || read(io, 0x9920)? & 0x10000 != 0
        {
            return Err(BringUpError::BadState);
        }
        self.state = State::Running;
        let attempt = Attempt {
            state: &mut self.state,
        };
        // Closed-loop def targets, per-band CTL and the ceiling are
        // intersected (and validated) before the PHY is activated.
        power::program(io, identity, image, tune, permission.ceiling)?;
        // ar9002_hw_configpcipowersave(ah, false): iniPcieSerdes and
        // AR9280_WA_DEFAULT, gated by ath9k_hw_configpcipowersave.
        pcie_pm::configure_ar9280(io, aspm, false)?;
        // ar5008_hw_init_bb: an OFDM channel (both bands here) waits
        // RX_DELAY / 10 + 100 us for the synthesizer.
        let delay = read(io, 0x9914)? & 0x3fff;
        write(io, 0x981c, 1)?;
        io.settle(u64::from(delay / 10 + 100)).await;
        ar9287::agc(io, true).await?;
        let (measured_noise_dbm, noise_dbm) = ar9287::noise(io, rx_chainmask, limits(tune)).await?;
        let iq = ar9287::iq(io, rx_chainmask, VERSION).await?;
        if read(io, 8)? & 4 != 0
            || read(io, 0x840)? & 0x3ff != 0
            || read(io, 0x24)? & 1 != 0
            || read(io, 0x981c)? & 1 != 1
            || read(io, 0x8048)? & 0x02000020 != 0x02000020
            || read(io, 0x982c)? & 0x8000 == 0
        {
            return Err(BringUpError::BadState);
        }
        let report = Report {
            country: permission.country,
            frequency_mhz: permission.frequency,
            five_ghz: tune.is_5ghz(),
            max_power_half_dbm: permission.ceiling,
            rx_chainmask,
            iq,
            measured_noise_dbm,
            noise_dbm,
        };
        self.report = Some(report);
        *attempt.state = State::Ready;
        Ok(report)
    }
}

/// The periodic owner of one AR9280 generation: the AR9287 20 MHz
/// `ar9002_hw_calibrate` state machine with the report band's NF limits,
/// the AR9280 `AR_SREV` version and no open-loop temperature step.
pub(in crate::ath9k) fn periodic(report: &Report, now_ms: u64) -> ar9287::Periodic {
    let limits = if report.five_ghz {
        LIMITS_5GHZ
    } else {
        LIMITS_2GHZ
    };
    ar9287::Periodic::with(report.rx_chainmask, None, limits, VERSION, now_ms)
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
