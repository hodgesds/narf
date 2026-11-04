// SPDX-License-Identifier: GPL-2.0-or-later
//! System suspend/resume of an owned SDIO card and its SDHCI host.
//!
//! Linux composition (7.3-rc4): the function driver requests host PM flags
//! (`sdio_set_host_pm_flags`), then `mmc/core/sdio.c::mmc_sdio_suspend`
//! (keep power: drop to 1-bit when the card interrupt must wake, else
//! `mmc_power_off`) and `mmc/host/sdhci.c::sdhci_suspend_host`
//! (`sdhci_enable_irq_wakeups`: `WAKE_UP_CONTROL` `WAKE_ON_INT`, only
//! `INT_CARD_INT` enabled, `enable_irq_wake(host->irq)`; otherwise every
//! interrupt enable cleared). Resume is `sdhci_resume_host`
//! (`sdhci_init(host, soft = KEEP_POWER)`: CMD/DATA-line reset and `set_ios`
//! replay of power, bus width, timing and clock; `sdhci_disable_irq_wakeups`)
//! followed by `mmc_sdio_resume` (keep power: restore the 4-bit bus; power
//! off: `mmc_sdio_reinit_card`). The same power-off/reinit halves serve
//! `mmc_hw_reset` ([`Card::hw_reset`]).

use super::*;
use crate::sdio::function::PmFlags;

#[derive(Clone, Copy, Debug)]
pub(super) struct Suspended {
    flags: PmFlags,
    /// `host->ier` analogue: interrupt status/signal enables to restore.
    int_enable: u32,
    signal_enable: u32,
    /// `sdio_disable_wide` dropped a 4-bit bus to 1-bit for the wake.
    narrowed: bool,
}

const SDHCI_WAKE_MASK: u8 = WAKE_ON_INT | WAKE_ON_INSERT | WAKE_ON_REMOVE;

impl<R: Registers> Card<R> {
    /// Linux `sdio_get_host_pm_caps`: the platform's grant, with
    /// `WAKE_SDIO_IRQ` only when a card-interrupt line is bound (the SDHCI
    /// wake is the host's own interrupt, `sdhci_enable_irq_wakeups`).
    pub fn host_pm_caps(&mut self) -> PmFlags {
        let caps = self.controller.registers().pm_caps();
        if self.interrupt.is_some() {
            caps
        } else {
            caps.without(PmFlags::WAKE_SDIO_IRQ)
        }
    }
    /// Whether a system suspend is held.
    pub fn suspended(&self) -> bool {
        self.suspend.is_some()
    }
    pub(super) fn suspend_host(&mut self, flags: PmFlags) -> Result<(), SdioError> {
        self.pm_gate()?;
        // sdio_set_host_pm_flags: -EINVAL for a flag the host lacks.
        if !self.host_pm_caps().contains(flags)
            || (flags.contains(PmFlags::WAKE_SDIO_IRQ) && !flags.contains(PmFlags::KEEP_POWER))
        {
            return Err(SdioError::Unsupported);
        }
        let io = self.controller.registers();
        let state = io.read32(PRESENT_STATE);
        if state == u32::MAX {
            return Err(SdioError::HostError);
        }
        if state & (PS_CMD_INHIBIT | PS_DATA_INHIBIT | PS_DOING_READ | PS_DOING_WRITE) != 0 {
            return Err(SdioError::Busy);
        }
        if !flags.contains(PmFlags::KEEP_POWER) {
            self.power_off_for_suspend(flags);
            return Ok(());
        }
        let wake = flags.contains(PmFlags::WAKE_SDIO_IRQ);
        if wake {
            // The card must be able to signal: CCCR IENM (sdio_claim_irq).
            if self.direct(false, 0, CCCR_INT_ENABLE, 0)? & 1 == 0 {
                return Err(SdioError::NotEnabled);
            }
            // sdhci_enable_irq_wakeups: wake only if enable_irq_wake holds.
            let armed = self
                .interrupt
                .as_ref()
                .is_some_and(|interrupt| interrupt.line.set_wake(true));
            if !armed {
                return Err(SdioError::Unsupported);
            }
        }
        // mmc_sdio_suspend: sdio_disable_4bit_bus for a waking card (the
        // 1-bit DAT1 interrupt is asynchronous, `SDIO_BUS_ASYNC_INT`).
        let mut narrowed = false;
        if wake && self.host.bus_width == 4 {
            let narrowed_bus = self.direct(false, 0, CCCR_BUS_IFACE, 0).and_then(|ctrl| {
                if ctrl & BUS_IFACE_BW_MASK != BUS_IFACE_BW_4BIT {
                    return Ok(false);
                }
                let ctrl = (ctrl & !BUS_IFACE_BW_MASK) | BUS_IFACE_ASYNC_INT;
                self.direct(true, 0, CCCR_BUS_IFACE, ctrl).map(|_| true)
            });
            match narrowed_bus {
                Ok(done) => narrowed = done,
                Err(error) => {
                    if let Some(interrupt) = self.interrupt.as_ref() {
                        interrupt.line.set_wake(false);
                    }
                    return Err(error);
                }
            }
            if narrowed {
                let io = self.controller.registers();
                let control = io.read8(HOST_CONTROL);
                io.write8(HOST_CONTROL, control & !CTRL_4BITBUS);
            }
        }
        let io = self.controller.registers();
        let int_enable = io.read32(INT_ENABLE);
        let signal_enable = io.read32(SIGNAL_ENABLE);
        if wake {
            let control = io.read8(WAKE_UP_CONTROL);
            io.write8(WAKE_UP_CONTROL, (control & !SDHCI_WAKE_MASK) | WAKE_ON_INT);
            io.write32(INT_ENABLE, INT_CARD_INT);
            io.write32(SIGNAL_ENABLE, INT_CARD_INT);
            // A delivered-but-unserviced line is masked: a still-asserted
            // card interrupt must wake (or abort) the suspend.
            if let Some(interrupt) = self.interrupt.as_ref() {
                interrupt.line.unmask();
            }
        } else {
            io.write32(INT_ENABLE, 0);
            io.write32(SIGNAL_ENABLE, 0);
        }
        self.suspend = Some(Suspended {
            flags,
            int_enable,
            signal_enable,
            narrowed,
        });
        Ok(())
    }
    /// `mmc_power_off`: SD clock and SDHCI bus power off (`sdhci_set_power`
    /// clearing `SDHCI_POWER_CONTROL`); the card loses every function,
    /// enable and receipt.
    fn power_off(&mut self) {
        self.live.retire();
        self.enabled = 0;
        self.observing = 0;
        self.block_sizes = [0; 8];
        let io = self.controller.registers();
        io.write32(SIGNAL_ENABLE, 0);
        io.write32(INT_ENABLE, 0);
        io.write16(CLOCK_CONTROL, 0);
        io.write8(POWER_CONTROL, 0);
        self.host.current_clock_hz = 0;
        self.host.card_selected = false;
    }
    fn power_off_for_suspend(&mut self, flags: PmFlags) {
        self.power_off();
        self.suspend = Some(Suspended {
            flags,
            int_enable: 0,
            signal_enable: 0,
            narrowed: false,
        });
    }
    /// Host-side stop of an owned card (Linux `brcmf_sdio_bus_reset`
    /// before `mmc_hw_reset`, and the power-off half of
    /// `mmc_power_cycle`): card-interrupt delivery retired, bus power and
    /// clock off, with the SDHCI registers read back as the receipt. An
    /// SDIO card cannot master host memory and every PIO/DMA command
    /// completed synchronously, so nothing of the host remains published.
    pub(super) fn power_off_host(&mut self) -> Result<(), SdioError> {
        if self.suspend.is_some() {
            return Err(SdioError::Busy);
        }
        if let Some(interrupt) = self.interrupt.as_ref() {
            interrupt.subscriber.clear();
        }
        self.power_off();
        let io = self.controller.registers();
        let state = io.read32(PRESENT_STATE);
        if state == u32::MAX
            || io.read8(POWER_CONTROL) & POWER_ON != 0
            || io.read16(CLOCK_CONTROL) & CLK_CARD_EN != 0
            || state & (PS_CMD_INHIBIT | PS_DATA_INHIBIT | PS_DOING_READ | PS_DOING_WRITE) != 0
        {
            return Err(SdioError::HostError);
        }
        Ok(())
    }
    /// Linux `mmc_hw_reset` -> `mmc_sdio_hw_reset` for an exclusively owned
    /// card: `mmc_power_cycle` (`mmc_power_off`, its 1 ms, at least 1 ms
    /// more per the SD spec, `mmc_power_up` with `ios.power_delay_ms` 10
    /// before and after the clock) then `mmc_sdio_reinit_card` (CCCR
    /// `sdio_reset`, CMD0, CMD5, CMD3, CMD7, CCCR/CIS) requiring the same
    /// function count and per-function vendor/device (`mmc_sdio_init_card`
    /// with `oldcard`: `-ENOENT` otherwise). Functions come back disabled
    /// and every earlier receipt retired. Whether the card's own supply
    /// follows SDHCI bus power is board wiring this host does not know; the
    /// CCCR I/O reset is what Linux relies on when it does not. Failure is
    /// terminal: the card stays powered off and every access is refused.
    pub(super) fn hw_reset(&mut self) -> Result<(), SdioError> {
        if self.suspend.is_some() {
            return Err(SdioError::Busy);
        }
        if let Some(interrupt) = self.interrupt.as_ref() {
            interrupt.subscriber.clear();
        }
        self.power_off();
        // mmc_power_off: 1 ms; mmc_power_cycle: "at least 1 ms".
        Self::delay(1_000);
        Self::delay(1_000);
        match self.reinit() {
            Ok(()) => {
                self.pm_failed = false;
                Ok(())
            }
            Err(error) => {
                self.pm_failed = true;
                self.power_off();
                Err(error)
            }
        }
    }
    /// Linux `sdio.c::sdio_reset` (SDIO Simplified Specification 4.4): set
    /// CCCR I/O Abort RES, keeping the read value when it answers. Errors
    /// are ignored as in `mmc_sdio_pre_init`; an errored command resets the
    /// host's command/data engines as `sdhci_request_done` does.
    pub(super) fn sdio_reset(&mut self) {
        let read = cmd52_arg(false, 0, false, CCCR_IO_ABORT, 0);
        let abort = match self.controller.execute(52, read, Response::R5, None) {
            Ok(value) => r5_data(value) | IO_ABORT_RES,
            Err(_) => {
                self.recover_command();
                IO_ABORT_RES
            }
        };
        let write = cmd52_arg(true, 0, false, CCCR_IO_ABORT, abort);
        if self
            .controller
            .execute(52, write, Response::R5, None)
            .is_err()
        {
            self.recover_command();
        }
    }
    fn recover_command(&mut self) {
        let io = self.controller.registers();
        io.write8(SOFTWARE_RESET, RESET_CMD | RESET_DATA);
        let _ = self.controller.wait(Deadline::after_us(100_000), |io| {
            let value = io.read8(SOFTWARE_RESET);
            if value == u8::MAX {
                Err(HostError::Gone)
            } else {
                Ok(value & (RESET_CMD | RESET_DATA) == 0)
            }
        });
        self.controller.revive();
    }
    pub(super) fn resume_host(&mut self) -> Result<(), SdioError> {
        if self.pm_failed {
            return Err(SdioError::HostError);
        }
        let Some(state) = self.suspend.take() else {
            return Err(SdioError::NotEnabled);
        };
        let result = if state.flags.contains(PmFlags::KEEP_POWER) {
            self.resume_powered(state)
        } else {
            self.resume_reinit()
        };
        if result.is_err() {
            self.pm_failed = true;
            self.live.retire();
            if let Some(interrupt) = self.interrupt.as_ref() {
                interrupt.line.set_wake(false);
            }
        }
        result
    }
    /// `sdhci_resume_host` (soft init + `set_ios`), then `mmc_sdio_resume`
    /// with power kept. The card was neither re-enumerated nor deselected,
    /// so its CCCR function enables are the receipt that it kept power.
    fn resume_powered(&mut self, state: Suspended) -> Result<(), SdioError> {
        let io = self.controller.registers();
        io.write8(SOFTWARE_RESET, RESET_CMD | RESET_DATA);
        self.controller
            .wait(Deadline::after_us(100_000), |io| {
                let value = io.read8(SOFTWARE_RESET);
                if value == u8::MAX {
                    Err(HostError::Gone)
                } else {
                    Ok(value & (RESET_CMD | RESET_DATA) == 0)
                }
            })
            .map_err(|_| SdioError::HostError)?;
        let mut control = 0;
        if self.host.high_speed {
            control |= CTRL_HISPD;
        }
        if self.host.bus_width == 4 && !state.narrowed {
            control |= CTRL_4BITBUS;
        }
        let io = self.controller.registers();
        io.write8(HOST_CONTROL, control);
        // set_ios: a host that lost its registers in the sleep state is
        // reprogrammed; a card that lost power fails the receipt below.
        io.write8(POWER_CONTROL, POWER_330 | POWER_ON);
        let clock = self.host.current_clock_hz;
        self.set_clock(clock).map_err(|_| SdioError::HostError)?;
        let io = self.controller.registers();
        // sdhci_disable_irq_wakeups.
        let wake = io.read8(WAKE_UP_CONTROL);
        io.write8(WAKE_UP_CONTROL, wake & !SDHCI_WAKE_MASK);
        io.write32(INT_STATUS, INT_ALL_MASK & !INT_CARD_INT);
        io.write32(INT_ENABLE, state.int_enable);
        io.write32(SIGNAL_ENABLE, state.signal_enable);
        if let Some(interrupt) = self.interrupt.as_ref() {
            interrupt.line.set_wake(false);
        }
        let io_enable = self.direct(false, 0, CCCR_IO_ENABLE, 0)?;
        if io_enable & 0xfe != self.enabled {
            return Err(SdioError::HostError);
        }
        if state.narrowed {
            // sdio_enable_4bit_bus -> sdio_enable_wide.
            let ctrl = self.direct(false, 0, CCCR_BUS_IFACE, 0)?;
            self.direct(
                true,
                0,
                CCCR_BUS_IFACE,
                (ctrl & !BUS_IFACE_BW_MASK) | BUS_IFACE_BW_4BIT,
            )?;
            let io = self.controller.registers();
            let control = io.read8(HOST_CONTROL);
            io.write8(HOST_CONTROL, control | CTRL_4BITBUS);
        }
        // mmc_sdio_resume wakes the SDIO IRQ thread for a pending source.
        if let Some(interrupt) = self.interrupt.as_ref() {
            interrupt.line.unmask();
        }
        Ok(())
    }
    /// `mmc_sdio_reinit_card` after `mmc_power_up`: full enumeration of
    /// the same card (identity per function must match). Functions are
    /// left disabled for their driver to probe again.
    fn resume_reinit(&mut self) -> Result<(), SdioError> {
        self.reinit()
    }
    fn reinit(&mut self) -> Result<(), SdioError> {
        let before = self.functions;
        let count = self.host.func_count;
        self.live = crate::source::Lifetime::new();
        // The power cycle precedes the host RESET_ALL in `start`; no
        // command of the previous lifetime is in flight.
        self.controller.revive();
        self.start(self.config, true)
            .map_err(|_| SdioError::HostError)?;
        if self.host.func_count != count
            || (0..=usize::from(count)).any(|f| {
                (before[f].vendor, before[f].device)
                    != (self.functions[f].vendor, self.functions[f].device)
            })
        {
            return Err(SdioError::HostError);
        }
        Ok(())
    }
}
