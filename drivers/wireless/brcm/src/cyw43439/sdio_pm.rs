// SPDX-License-Identifier: GPL-2.0-or-later
//! CYW43439 SDIO system suspend/resume with the dongle kept powered
//! (Linux 7.3-rc4 brcmfmac `bcmsdh.c::brcmf_ops_sdio_suspend` /
//! `brcmf_ops_sdio_resume`, `brcmf_sdiod_freezer_on/off`,
//! `sdio.c::brcmf_sdio_sleep` -> `brcmf_sdio_bus_sleep`).
//!
//! Suspend: the bus sleeps (`brcmf_sdio_bus_sleep(.., true, false)`: KSO
//! clear on save-restore chips, otherwise `brcmf_sdio_clkctl(CLK_NONE)`
//! dropping the backplane clock request), then the host is suspended with
//! `MMC_PM_KEEP_POWER`, plus `MMC_PM_WAKE_SDIO_IRQ` when WoWL is armed
//! (`sdio_set_host_pm_flags`). Linux's alternative for a host that can cut
//! card power (`MMC_CAP_POWER_OFF_CARD` without WoWL) removes the device
//! and probes it again on resume; NARF has no SDIO re-probe/WL_REG_ON owner
//! (`transport_reset` is open), so a host without keep-power refuses and
//! the system-PM coordinator unwinds. A platform out-of-band wake line
//! (`oob_irq_supported` + `enable_irq_wake`) has no in-tree board owner.
//!
//! Resume: host resume (the card's function enables prove it kept power),
//! then `brcmf_sdio_bus_sleep(.., false, ..)`: KSO set + HT available on SR
//! chips, `CLK_AVAIL` (`brcmf_sdio_htclk` HT request + HT available)
//! otherwise.
use super::*;
use narf_drivers_sdio::PmFlags;

/// `SBSDIO_HT_AVAIL_REQ`, the non-SR standing backplane clock request.
const HT_AVAIL_REQ: u8 = 0x10;

#[derive(Clone, Copy, Debug)]
pub(super) struct Suspended {
    /// Non-SR chips: the clock request was dropped (`CLK_NONE`).
    clock_dropped: bool,
}

impl<F: SdioFunction> SdioTransport<F> {
    /// `brcmf_sdio_probe_attach`: `wowl_supported` needs
    /// `MMC_PM_KEEP_POWER` and `MMC_PM_WAKE_SDIO_IRQ` (no OOB line here),
    /// and the card interrupt claimed by `initialize_packets`.
    pub fn wowl_supported(&mut self) -> bool {
        !self.failed
            && !self.stopped
            && self.interrupt.is_some()
            && self
                .func
                .host_pm_caps()
                .contains(PmFlags::KEEP_POWER.union(PmFlags::WAKE_SDIO_IRQ))
    }

    pub(super) fn suspend_bus(&mut self, wake: bool) -> Result<(), TransportError> {
        self.check_qualification()?;
        if self.stopped || self.packet_core.is_none() {
            return Err(TransportError::NotReady);
        }
        if self.suspended.is_some() {
            return Err(TransportError::Busy);
        }
        let caps = self.func.host_pm_caps();
        let mut flags = PmFlags::KEEP_POWER;
        if wake {
            flags = flags.union(PmFlags::WAKE_SDIO_IRQ);
        }
        // Refuse before touching the dongle so the unwind finds it awake.
        if !caps.contains(flags) || (wake && self.interrupt.is_none()) {
            return Err(TransportError::NotReady);
        }
        // brcmf_sdiod_freezer_on -> brcmf_sdio_sleep(bus, true).
        let clock_dropped = match self.sleep {
            Some(sleep) => {
                if !sleep.asleep {
                    if let Err(error) = self.enter_sleep() {
                        self.failed = true;
                        return Err(error);
                    }
                }
                false
            }
            None => {
                // brcmf_sdio_htclk(bus, false, ..): clkreq = 0.
                if let Err(error) = self
                    .func
                    .cmd52_write(1, sdio::F1_CHIPCLK_CTRL, 0)
                    .map_err(map_err)
                {
                    self.failed = true;
                    return Err(error);
                }
                true
            }
        };
        // sdio_set_host_pm_flags + mmc_sdio_suspend + host suspend.
        if let Err(error) = self.func.suspend_host(flags) {
            // The host is unchanged: wake the dongle back up for the unwind.
            let woken = if clock_dropped {
                self.request_ht()
            } else {
                self.wake()
            };
            if woken.is_err() {
                self.failed = true;
            }
            return Err(match error {
                SdioError::Unsupported => TransportError::NotReady,
                SdioError::Busy => TransportError::Busy,
                other => map_err(other),
            });
        }
        self.suspended = Some(Suspended { clock_dropped });
        Ok(())
    }

    pub(super) fn resume_bus(&mut self) -> Result<(), TransportError> {
        let Some(state) = self.suspended.take() else {
            return Err(TransportError::Busy);
        };
        let result = self
            .func
            .resume_host()
            .map_err(map_err)
            .and_then(|()| self.check_qualification())
            .and_then(|()| {
                // brcmf_sdiod_freezer_off -> brcmf_sdio_sleep(bus, false).
                if state.clock_dropped {
                    self.request_ht()
                } else {
                    self.wake()
                }
            });
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// `brcmf_sdio_htclk(bus, true, false)`: request HT, wait for it
    /// (`PMU_MAX_TRANSITION_DLY`).
    fn request_ht(&mut self) -> Result<(), TransportError> {
        self.func
            .cmd52_write(1, sdio::F1_CHIPCLK_CTRL, HT_AVAIL_REQ)
            .map_err(map_err)?;
        let mut failure = None;
        let ok = narf_scheduler::responsive_spin_until(
            || match self.func.cmd52_read(1, sdio::F1_CHIPCLK_CTRL) {
                Ok(read) => read & chipclk::HT_AVAIL != 0,
                Err(error) => {
                    failure = Some(error);
                    true
                }
            },
            narf_time::Deadline::after_us(KSO_TIMEOUT_US),
        );
        if let Some(error) = failure {
            return Err(map_err(error));
        }
        if !ok {
            return Err(TransportError::Timeout);
        }
        Ok(())
    }
}
