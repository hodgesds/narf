// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Actual register-mailbox PHY capability receipt on the retained Native.
use super::*;
use crate::rtw89::{firmware_phycap::Receipt, power, scheduler_mailbox};

struct Port<'a>(&'a mut Native);
impl power::Io for Port<'_> {
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        self.0.io.read8(a)
    }
    fn read16(&mut self, a: u32) -> Result<u16, power::Error> {
        self.0.io.read16(a)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.0.io.read32(a)
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        self.0.io.write8(a, v)
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), power::Error> {
        self.0.io.write16(a, v)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.0.io.write32(a, v)
    }
    fn now_us(&self) -> u64 {
        self.0.io.now_us()
    }
    async fn delay_us(&mut self, us: u64) {
        self.0.io.delay_us(us).await;
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl scheduler_mailbox::Interface for Port<'_> {
    fn admit(&mut self) -> Result<(), power::Error> {
        let authority = self.0.authority;
        crate::rtw88::pci_park::invoke(&authority, || {
            if self.0.state != State::Active
                || self.0.chip != ChipId::Rtl8852B
                || !self.0.phycap_attempted
                || self.0.phycap.is_some()
                || self.0.radio_started
                || self.0.calibration.is_some()
                || self.0.coex_ready
                || self.0.nctl_ready
            {
                return Err(power::Error::Terminal);
            }
            self.0.radio_access()
        })
        .map_err(|_| power::Error::Access)?
    }
}
struct Attempt<'a> {
    native: &'a mut Native,
    mailbox: Option<scheduler_mailbox::Mailbox>,
    committed: bool,
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        self.native.scheduler = self.mailbox.take();
        if !self.committed {
            self.native.fail();
        }
    }
}
impl Native {
    /// Query once, before BB/RF tables or calibration. The exact mailbox and
    /// its counters/pending state are returned to this Native even on cancel.
    pub(in crate::rtw89) async fn query_firmware_phycap(&mut self) -> Result<(), power::Error> {
        if self.phycap_attempted || self.phycap.is_some() {
            return Err(power::Error::Terminal);
        }
        self.phycap_attempted = true;
        let mailbox = self.scheduler.take().ok_or(power::Error::Terminal)?;
        let mut attempt = Attempt {
            native: self,
            mailbox: Some(mailbox),
            committed: false,
        };
        let receipt = attempt
            .mailbox
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .phycap(&mut Port(&mut *attempt.native))
            .await?;
        receipt.initial_profile()?;
        attempt.native.phycap = Some(receipt);
        attempt.native.phy_profile_current()?;
        attempt.committed = true;
        Ok(())
    }
    pub(super) fn firmware_phycap(&self) -> Option<&Receipt> {
        self.phycap.as_ref()
    }
    pub(super) fn phy_profile_current(&self) -> Result<(), power::Error> {
        crate::rtw88::pci_park::invoke(&self.authority, || {
            if self.state != State::Active
                || self.chip != ChipId::Rtl8852B
                || self
                    .factory
                    .as_ref()
                    .and_then(|factory| factory.identity())
                    .is_none_or(|identity| identity.chip() != ChipId::Rtl8852B)
            {
                return Err(power::Error::Terminal);
            }
            self.phycap
                .as_ref()
                .ok_or(power::Error::Unsupported)?
                .initial_profile()
        })
        .map_err(|_| power::Error::Access)?
    }
}
