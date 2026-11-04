// SPDX-License-Identifier: GPL-2.0-or-later
//! Original SDIO PIO owner retirement. No power rail, reset/reboot or DMA
//! receipt is inferred from a local failed flag or from CPU IRQ quarantine.
use super::*;

struct Backplane<'a, F: SdioFunction>(&'a mut SdioTransport<F>);
impl<F: SdioFunction> crate::brcmfmac::chip::Backplane for Backplane<'_, F> {
    fn read32(&mut self, address: u32) -> Result<u32, crate::brcmfmac::chip::Error> {
        self.0
            .read_backplane(address)
            .map_err(|_| crate::brcmfmac::chip::Error::Access)
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), crate::brcmfmac::chip::Error> {
        self.0
            .write_backplane(address, value)
            .map_err(|_| crate::brcmfmac::chip::Error::Access)
    }
}
impl<F: SdioFunction> SdioTransport<F> {
    fn stop_native(&mut self) -> Result<(), TransportError> {
        self.check_qualification()?;
        let core = self.packet_core.ok_or(TransportError::NotReady)?;
        self.wake()?;
        let passive = super::super::sdio_passive::prepare(&mut Backplane(self), core)
            .map_err(|_| TransportError::NotReady)?;
        // brcmf_sdio_bus_stop: wake, mask original SDIO-core interrupts,
        // keep HT available for F2 propagation, disable F2, then W1C status.
        let original_mask = self.read_backplane(core + 0x24)?;
        if original_mask == u32::MAX {
            return Err(TransportError::NotReady);
        }
        self.write_backplane(core + 0x24, 0)?;
        if self.read_backplane(core + 0x24)? != 0 {
            return Err(TransportError::NotReady);
        }
        let clock = self
            .func
            .cmd52_read(1, sdio::F1_CHIPCLK_CTRL)
            .map_err(map_err)?;
        self.func
            .cmd52_write(1, sdio::F1_CHIPCLK_CTRL, clock | chipclk::FORCE_HT_REQ)
            .map_err(map_err)?;
        let mut failure = None;
        let available = narf_scheduler::responsive_spin_until(
            || match self.func.cmd52_read(1, sdio::F1_CHIPCLK_CTRL) {
                Ok(value) => value & chipclk::HT_AVAIL != 0,
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
        if !available {
            return Err(TransportError::Timeout);
        }
        self.func.disable_func(2).map_err(map_err)?;
        self.write_backplane(core + 0x20, original_mask)?;
        if self.read_backplane(core + 0x20)? & original_mask != 0 {
            return Err(TransportError::NotReady);
        }
        // brcmf_sdio_remove: the exact43439 CM3/D11/SOCRAM passive sequence,
        // independently qualified by the original signed/native host owner.
        // Linux remove leaves an actual20ms settling interval before putting
        // CM3/D11/RAM passive. Use the shared bounded pump primitive.
        let _ = narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_ms(20));
        super::super::sdio_passive::enter(&mut Backplane(self), &passive)
            .map_err(|_| TransportError::NotReady)?;
        self.func
            .cmd52_write(1, sdio::F1_CHIPCLK_CTRL, 0)
            .map_err(map_err)?;
        let clock = self
            .func
            .cmd52_read(1, sdio::F1_CHIPCLK_CTRL)
            .map_err(map_err)?;
        if clock & 0x3f != 0 {
            return Err(TransportError::NotReady);
        }
        self.func.disable_func(1).map_err(map_err)?;
        self.check_qualification()
    }
    pub(super) fn confirmed_stop(&mut self) -> Result<(), TransportError> {
        if self.stopped {
            return Ok(());
        }
        // CPU routing must be retired even when prior protocol/transport
        // failure or current original source makes device stop unprovable.
        let irq = self.func.disable_card_interrupt().map_err(map_err);
        self.interrupt = None;
        let native = self.stop_native();
        self.failed = true;
        self.sleep = None;
        self.rx_pending = false;
        self.flow_stopped = true;
        irq?;
        native?;
        self.stopped = true;
        Ok(())
    }
    /// `brcmf_sdio_bus_reset` before `mmc_hw_reset`:
    /// `brcmf_sdiod_intr_unregister`, best-effort `brcmf_sdiod_remove`
    /// (the native stop, attempted only when the generation is still
    /// qualified), then the host bus power off with its SDHCI read-back
    /// (`SdioFunction::power_off_host`). The card loses every function
    /// and receipt; only [`Self::into_function`] plus `hw_reset` follow.
    pub(super) fn stop_dead(&mut self) -> Result<(), TransportError> {
        if self.stopped {
            return Ok(());
        }
        let _ = self.func.disable_card_interrupt();
        self.interrupt = None;
        if !self.failed {
            let _ = self.stop_native();
        }
        self.failed = true;
        self.sleep = None;
        self.rx_pending = false;
        self.flow_stopped = true;
        self.func.power_off_host().map_err(map_err)?;
        self.stopped = true;
        Ok(())
    }
    /// A fatal transport error (as a failed FIFO access records).
    #[cfg(feature = "kernel-test")]
    pub(crate) fn fail_for_test(&mut self) {
        self.failed = true;
    }
    /// The whole card of a stopped generation, for its reset. A generation
    /// without a stop is pinned (forgotten) instead.
    pub(crate) fn into_function(self) -> Option<F> {
        if !self.stopped {
            core::mem::forget(self);
            return None;
        }
        Some(self.func)
    }
}
