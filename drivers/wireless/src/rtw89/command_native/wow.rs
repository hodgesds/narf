// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Reversible RTL8852B WoW TRX halt/restart on the one retained Native
//! (`wow.c::rtw89_wow_enable_trx_{pre,post}` / `disable_trx_{pre,post}`).
//! The owner keeps PCI bus mastering, every ring/buffer mapping, the IRQ
//! vector and its MSI binding; only the HIMR mask is cleared while the WoW
//! firmware owns the radio. Any failure terminalizes through `fail`, whose
//! existing closure earns the `dma_stop` proof for the cold path.
use super::*;
use crate::rtw89::{
    power,
    wow_trx::{self, CpuIoRx, Ring, Snapshot},
};
use alloc::vec::Vec;

/// Bound on waiting for in-flight CH12 commands before the halt rewinds it.
const H2C_DRAIN_US: u64 = 10_000;

/// Progress of one WoW TRX window.
pub(super) enum Trx {
    /// `enable_trx_pre` done: host TX halted, CH12 open, RX filtered out.
    Quiesced(Snapshot),
    /// `enable_trx_post` done: HCI off, host indices and ring bases reset.
    Parked(Snapshot, Vec<Ring>),
    /// `disable_trx_pre` done: indices cleared, HCI and channels re-opened.
    Restarted(Snapshot),
}

impl Native {
    /// True while a WoW TRX window is open; packet producers and station RX
    /// polling are refused.
    pub(in crate::rtw89) fn wow_trx_open(&self) -> bool {
        self.wow_trx.is_some()
    }
    /// True only between `enable_trx_post` and `disable_trx_pre`, when the
    /// HCI DMA engines are off and CH12 cannot carry a command.
    pub(super) fn wow_parked(&self) -> bool {
        matches!(self.wow_trx, Some(Trx::Parked(..)))
    }
    fn wow_failed<T>(&mut self, error: wow_trx::Error) -> Result<T, power::Error> {
        self.wow_trx = None;
        self.fail();
        Err(match error {
            wow_trx::Error::Register(error) => error,
            wow_trx::Error::Unsupported => power::Error::Unsupported,
            wow_trx::Error::Timeout | wow_trx::Error::TxBusy | wow_trx::Error::Queue => {
                power::Error::Timeout
            }
            _ => power::Error::Access,
        })
    }
    /// `rtw89_wow_enable_trx_pre` on a started, transmit-quiet RTL8852B
    /// station outside LPS. Refusing preconditions leave the station awake
    /// and untouched (`Busy`/`Terminal`); a register failure terminalizes.
    pub(in crate::rtw89) async fn wow_trx_enter_pre(&mut self) -> Result<(), power::Error> {
        if self.chip != ChipId::Rtl8852B
            || self.state != State::Active
            || !self.station_runtime.started()
            || self.station_runtime.monitor.is_some()
            || self.wow_trx.is_some()
            || self.sleep_blocked
            || self.sleep_reset.is_some()
        {
            return Err(power::Error::Terminal);
        }
        self.ordinary_current()?;
        let core = self
            .station_runtime
            .core
            .as_mut()
            .ok_or(power::Error::Terminal)?;
        core.wow_halt().map_err(|_| power::Error::Busy)?;
        match wow_trx::enter_pre(&mut self.io).await {
            Ok(snapshot) => {
                self.wow_trx = Some(Trx::Quiesced(snapshot));
                Ok(())
            }
            Err(error) => self.wow_failed(error),
        }
    }
    /// `rtw89_wow_enable_trx_post` once the WoW firmware runs: HIMR off
    /// (`rtw89_hci_disable_intr`), every CH12 command consumed, then the
    /// register sequence with `rtw89_pci_ops_reset` (host TX/RX/CH12
    /// indices rewound, ring bases re-published, nothing released).
    pub(in crate::rtw89) async fn wow_trx_enter_post(
        &mut self,
        cpu_io_rx: CpuIoRx,
    ) -> Result<(), power::Error> {
        let Some(Trx::Quiesced(snapshot)) = self.wow_trx.take() else {
            self.fail();
            return Err(power::Error::Terminal);
        };
        if self.state != State::Active {
            return self.wow_failed(wow_trx::Error::State);
        }
        if self.irq.is_some() {
            if let Err(error) = crate::rtw89::irq::Mask::disable(&mut self.io) {
                return self.wow_failed(error.into());
            }
        }
        // Retire every consumed H2C before the CH12 host index rewinds
        // (Linux `rtw89_pci_release_fwcmd` drops unconsumed ones instead).
        let start = self.io.now_us();
        loop {
            if self.poll().is_err() {
                return self.wow_failed(wow_trx::Error::Queue);
            }
            if self.queue.pending() == 0 {
                break;
            }
            if self.io.now_us().saturating_sub(start) >= H2C_DRAIN_US {
                return self.wow_failed(wow_trx::Error::Queue);
            }
            self.io.delay_us(50).await;
        }
        let rings = match self.wow_rewind() {
            Ok(rings) => rings,
            Err(error) => return self.wow_failed(error),
        };
        if let Err(error) = wow_trx::enter_post(&mut self.io, cpu_io_rx, &rings).await {
            return self.wow_failed(error);
        }
        self.wow_trx = Some(Trx::Parked(snapshot, rings));
        Ok(())
    }
    /// Host halves of `rtw89_pci_reset_trx_rings` + `rtw89_pci_ops_reset`.
    fn wow_rewind(&mut self) -> Result<Vec<Ring>, wow_trx::Error> {
        let mut rings = Vec::new();
        let core = self
            .station_runtime
            .core
            .as_mut()
            .ok_or(wow_trx::Error::State)?;
        for (channel, regs, address, depth) in
            core.wow_rewind().map_err(|_| wow_trx::Error::Queue)?
        {
            rings.push(Ring::Tx {
                channel,
                regs,
                address,
                depth,
            });
        }
        self.queue.rewind().map_err(|_| wow_trx::Error::Queue)?;
        let ring = self.ring.as_ref().ok_or(wow_trx::Error::State)?;
        rings.push(Ring::Tx {
            channel: usize::from(crate::rtw89::dma::TXCH_CH12),
            regs: self.regs,
            address: ring.dma_addr().raw(),
            depth: self.depth,
        });
        for (regs, address, depth) in self
            .receive
            .wow_rewind()
            .map_err(|_| wow_trx::Error::State)?
        {
            rings.push(Ring::Rx {
                regs,
                address,
                depth,
            });
        }
        Ok(rings)
    }
    /// `rtw89_wow_disable_trx_pre`: clear device indices, reset BD-RAM,
    /// re-open HCI and the awake channels, restore the awake MAC forwarding,
    /// prove every published index zero, then `rtw89_hci_enable_intr`. The
    /// AOAC report read belongs to the firmware-swap owner.
    pub(in crate::rtw89) async fn wow_trx_leave_pre(&mut self) -> Result<(), power::Error> {
        let Some(Trx::Parked(snapshot, rings)) = self.wow_trx.take() else {
            self.fail();
            return Err(power::Error::Terminal);
        };
        if self.state != State::Active {
            return self.wow_failed(wow_trx::Error::State);
        }
        if let Err(error) = wow_trx::leave_pre(&mut self.io, &snapshot, &rings).await {
            return self.wow_failed(error);
        }
        if let Some(binding) = self.irq.as_ref() {
            if let Err(error) = binding.start(&mut self.io) {
                return self.wow_failed(error.into());
            }
        }
        self.wow_trx = Some(Trx::Restarted(snapshot));
        Ok(())
    }
    /// `rtw89_wow_disable_trx_post` after the normal firmware is restored:
    /// awake PPDU status and RX filters, then packet producers resume.
    pub(in crate::rtw89) fn wow_trx_leave_post(&mut self) -> Result<(), power::Error> {
        let Some(Trx::Restarted(snapshot)) = self.wow_trx.take() else {
            self.fail();
            return Err(power::Error::Terminal);
        };
        if self.state != State::Active {
            return self.wow_failed(wow_trx::Error::State);
        }
        if let Err(error) = wow_trx::leave_post(&mut self.io, snapshot) {
            return self.wow_failed(error);
        }
        let resumed = self
            .station_runtime
            .core
            .as_mut()
            .map(|core| core.wow_resume());
        if !matches!(resumed, Some(Ok(()))) {
            return self.wow_failed(wow_trx::Error::State);
        }
        Ok(())
    }
}
