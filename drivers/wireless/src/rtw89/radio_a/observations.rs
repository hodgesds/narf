// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Bounded original-owner observations, not channel calibration. Source:
//! rtw8852a.c `rtw8852a_get_thermal` non-TSSI branch and phy.c
//! `rtw89_phy_stat_thermal_update`, `DECLARE_EWMA(thermal, 4, 4)`.
use crate::rtw89::{
    rf_tracking::Thermal,
    rfk::{Error, Interface},
};

/// Bound separately into N5AB-v2/N5AC; historical cold N5AB-v1 is unchanged.
pub(in crate::rtw89) const RECIPE: &[u8] = b"RTL8852A retained post-channel non-TSSI observations v1: actual factory rtw8852a_fem_setup RFE switch, EPA/ELNA bands2G/5G; MAC0 packets remain closed; rfk_init is_tssi_mode A/B false; each RF42 BIT19 trigger1/0/1, fsleep200us, RF42 GENMASK6:1 sample; source DECLARE_EWMA thermal4,4 nonzero only; no factory-thermal fallback, no TSSI-mode/DPK/channel/station receipt; failure/drop terminal";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::rtw89) enum State {
    #[default]
    New,
    Busy,
    Observed,
}

/// Zero remains an unavailable live sample. Average zero means this path
/// has never produced a nonzero sample, not factory thermal or a default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) struct Snapshot {
    pub sample: [u8; 2],
    pub average: [u8; 2],
    pub last_thermal_max: u8,
}

#[derive(Default)]
pub(in crate::rtw89) struct Observations {
    state: State,
    average: [Thermal; 2],
    snapshot: Option<Snapshot>,
}
impl Observations {
    pub fn state(&self) -> State {
        self.state
    }
    pub fn snapshot(&self) -> Option<Snapshot> {
        (self.state == State::Observed)
            .then_some(self.snapshot)
            .flatten()
    }
    /// History survives a failed or dropped observation. It cannot be
    /// published as a fresh complete two-path sample after such an attempt.
    pub fn averages(&self) -> [u8; 2] {
        self.average.map(Thermal::read)
    }

    /// # Safety
    /// Exact original RTL8852A function after its retained `rfk_init`
    /// with both `is_tssi_mode` values still false. Actual signed recipe
    /// and original Bus authority enclose every effect through Interface;
    /// no concurrent TSSI/RFK/packet/reset/PM producer. Native preserves
    /// CMAC TX closure. Failure/drop leaves Busy without reconstructing
    /// this retained owner or allowing a retry.
    pub async unsafe fn non_tssi(&mut self, io: &mut impl Interface) -> Result<(), Error> {
        if self.state == State::Busy {
            return Err(Error::Terminal);
        }
        self.state = State::Busy;
        let mut sample = [0; 2];
        for path in 0..2u8 {
            for trigger in [1, 0, 1] {
                io.admit()?;
                io.rf_write(path, 0x42, 1 << 19, trigger).await?;
            }
            io.admit()?;
            io.delay_us(200).await;
            io.admit()?;
            let value = io.rf_read(path, 0x42, 0x7e).await?;
            // Native propagates access failure before field extraction.
            // Reject malformed generic sources rather than truncate them.
            let value = u8::try_from(value)
                .ok()
                .filter(|&v| v <= 63)
                .ok_or(Error::Table)?;
            io.admit()?;
            sample[usize::from(path)] = value;
            self.average[usize::from(path)].add(value);
        }
        io.admit()?;
        self.snapshot = Some(Snapshot {
            sample,
            average: self.averages(),
            last_thermal_max: sample[0].max(sample[1]),
        });
        self.state = State::Observed;
        Ok(())
    }
    /// # Safety
    /// Same actual A owner after completed TSSI enable on both paths; the
    /// retained radio supplies that source mode, not a caller assumption.
    /// No concurrent reset/PM/PHY/RFK producer; current grants enclose reads.
    pub async unsafe fn tssi(&mut self, io: &mut impl Interface) -> Result<(), Error> {
        if self.state == State::Busy {
            return Err(Error::Terminal);
        }
        self.state = State::Busy;
        let mut sample = [0; 2];
        for (path, value) in sample.iter_mut().enumerate() {
            io.admit()?;
            let raw = io.read32(0x11c10 + ((path as u32) << 13))?;
            if raw == u32::MAX {
                return Err(crate::rtw89::power::Error::Gone.into());
            }
            io.admit()?;
            *value = ((raw >> 24) & 0x3f) as u8;
            self.average[path].add(*value);
        }
        io.admit()?;
        self.snapshot = Some(Snapshot {
            sample,
            average: self.averages(),
            last_thermal_max: sample[0].max(sample[1]),
        });
        self.state = State::Observed;
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "observations_tests.rs"]
mod tests;
