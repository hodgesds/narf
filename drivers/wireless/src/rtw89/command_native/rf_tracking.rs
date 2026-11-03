// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained ordinary-owner DPK tracking. Initial RFK's CMAC-closed gate stays
//! unchanged: this is a separate exact register surface, not calibration IO.
use super::*;
use crate::rtw89::{power, rf_tracking, station_control::Admission};

struct TrackingPort<'a> {
    native: &'a mut Native,
    admission: &'a Admission,
    window: rf_tracking::Window,
}
impl rf_tracking::Hw for TrackingPort<'_> {
    fn current(&mut self) -> Result<(), power::Error> {
        if self.native.sleep_blocked {
            return Err(power::Error::Terminal);
        }
        crate::rtw89::station_control::awake(&mut self.native.io)?;
        self.admission.check()?;
        self.native.ordinary_current()?;
        if self
            .native
            .full_radio_scope()
            .ok_or(power::Error::Access)?
            .rf_tracking_window()
            .map_err(|_| power::Error::Access)?
            != Some(self.window)
        {
            return Err(power::Error::Access);
        }
        Ok(())
    }
    fn read_bb(&mut self, address: u32) -> Result<u32, power::Error> {
        if !rf_tracking::readable(address) {
            return Err(power::Error::Access);
        }
        self.current()?;
        self.admission.run(|| {
            self.native
                .with_ordinary_current(|native| native.io.read32(rf_tracking::BASE + address))
        })
    }
    fn write_bb(&mut self, address: u32, mask: u32, value: u32) -> Result<(), power::Error> {
        if !rf_tracking::writable(address) || mask != 0x01ff01ff || value & !mask != 0 {
            return Err(power::Error::Access);
        }
        let low = (value & 0x1ff) as u16;
        let high = ((value >> 16) & 0x1ff) as u16;
        if low != high || !(self.window.low..=self.window.high).contains(&low) {
            return Err(power::Error::Access);
        }
        self.current()?;
        self.admission.run(|| {
            self.native.with_ordinary_current(|native| {
                let target = rf_tracking::BASE + address;
                let old = native.io.read32(target)?;
                if old == u32::MAX {
                    return Err(power::Error::Gone);
                }
                native.io.write32(target, old & !mask | value)?;
                if native.io.read32(target)? & mask != value {
                    return Err(power::Error::Access);
                }
                Ok(())
            })
        })
    }
}
impl Native {
    pub(in crate::rtw89) fn station_rf_tracking(
        &mut self,
        admission: &Admission,
    ) -> Result<(), power::Error> {
        if self.sleep_blocked {
            return Err(power::Error::Terminal);
        }
        admission.check()?;
        self.ordinary_current()?;
        if self.chip == ChipId::Rtl8852C {
            // No signed C RF-tracking companion: the program does no RF work.
            return Ok(());
        }
        let Some(window) = self
            .full_radio_scope()
            .ok_or(power::Error::Access)?
            .rf_tracking_window()
            .map_err(|_| power::Error::Access)?
        else {
            return Ok(()); // The unchanged narrow program performs no RF work.
        };
        if !self.station_runtime.started() || self.calibrating.is_some() {
            return Err(power::Error::Terminal);
        }
        // Input was copied from the same actual Radio completion, before its
        // ordinary receipt was installed; never reconstructed from station flags.
        let Some(mut tracker) = self.station_runtime.rf_tracking.take() else {
            self.fail();
            return Err(power::Error::Terminal);
        };
        let result = tracker.step(
            &mut TrackingPort {
                native: self,
                admission,
                window,
            },
            window,
        );
        if result.is_ok() {
            self.station_runtime.rf_tracking = Some(tracker);
        } else {
            self.fail();
        }
        result
    }
}
