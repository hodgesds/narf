// SPDX-License-Identifier: GPL-2.0-or-later
//! Reversible host-DMA stop/restart of the retained native packet owner,
//! Linux 7.3-rc4 `rtw88/pci.c` `rtw_pci_stop` / `rtw_pci_setup` +
//! `rtw_pci_start` (via `rtw_hci_stop` / `rtw_hci_setup` / `rtw_hci_start`
//! in `wow.c`). Unlike `Port::stop`/`quiesce` (BME off, CR DMA gates off,
//! `State::Terminal`), the halted owner keeps PCI bus mastering, the MAC
//! and every published mapping, and only resets the ring pointers.
use super::{dma_address, Error, Native, Registers, State, RX_BYTES, RX_DEPTH};
use crate::rtw88::packet_core::Port;

/// `RTK_PCI_CTRL`: `BIT_RST_TRXDMA_INTF` | `BIT_RX_TAG_EN` (`rtw_pci_dma_reset`).
const PCI_CTRL: u16 = 0x0300;
const DMA_RESET: u32 = 1 << 20 | 1 << 15;
/// `RTK_PCI_TXBD_RWPTR_CLR`.
const RWPTR_CLR: u16 = 0x039c;
/// `RTK_PCI_TXBD_H2CQ_CSR`: `BIT_CLR_H2CQ_HOST_IDX` | `BIT_CLR_H2CQ_HW_IDX`.
const H2CQ_CSR: u16 = 0x1330;
const H2CQ_CLEAR: u32 = 1 << 16 | 1 << 8;
/// `RTK_PCI_RXBD_DESA_MPDUQ`, `RTK_PCI_RXBD_NUM_MPDUQ`, `RTK_PCI_RXBD_IDX_MPDUQ`.
const RX_BASE: u16 = 0x0338;
const RX_COUNT: u16 = 0x0382;
const RX_INDEX: u16 = 0x03b4;
/// `RTK_PCI_TXBD_DESA_BCNQ`.
const BEACON_BASE: u16 = 0x0308;

impl Native {
    /// `rtw_pci_reset_buf_desc`: reprogram every retained ring base/count
    /// (beacon, H2C, BK/BE/VO/VI/MGMT/HI0, RX MPDU), clear all TX/RX
    /// read/write pointers and the H2C queue indices, then prove every
    /// index reads zero. No mapping is replaced or released.
    fn reset_buf_desc(&mut self) -> Result<(), Error> {
        let config = self.read8(0x303)?;
        self.write8(0x303, config | 0xf7)?;
        let beacon = self.beacon.ok_or(Error::State)?;
        self.write32(BEACON_BASE, beacon)?;
        for slot in 0..self.tx.len() {
            let tx = &self.tx[slot];
            let (base, count, depth) = (tx.base, tx.count, tx.depth);
            let address = dma_address(&tx.memory, depth * 16)?;
            self.write16(count, depth as u16)?;
            self.write32(base, address)?;
            if self.read32(base)? != address || self.read16(count)? & 0xfff != depth as u16 {
                return Err(Error::Prerequisite);
            }
        }
        let rx = dma_address(self.rx.as_ref().ok_or(Error::State)?, RX_DEPTH * 8)?;
        self.write16(RX_COUNT, RX_DEPTH as u16)?;
        self.write32(RX_BASE, rx)?;
        if self.read32(BEACON_BASE)? != beacon
            || self.read32(RX_BASE)? != rx
            || self.read16(RX_COUNT)? & 0xfff != RX_DEPTH as u16
        {
            return Err(Error::Prerequisite);
        }
        self.write32(RWPTR_CLR, u32::MAX)?;
        let h2c = self.read32(H2CQ_CSR)?;
        if h2c == u32::MAX {
            return Err(Error::Gone);
        }
        self.write32(H2CQ_CSR, h2c | H2CQ_CLEAR)?;
        for slot in 0..self.tx.len() {
            let index = self.tx[slot].index;
            if self.read32(index)? & 0x0fff_0fff != 0 {
                return Err(Error::Prerequisite);
            }
        }
        if self.read32(RX_INDEX)? & 0x0fff_0fff != 0 {
            return Err(Error::Prerequisite);
        }
        self.command_ring = crate::rtw88::command::Ring::default();
        Ok(())
    }
    /// `rtw_pci_disable_interrupt`: NARF polls, so the three HIMRs are
    /// already zero; rewrite and prove them as the source does.
    fn mask_interrupts(&mut self) -> Result<(), Error> {
        for register in crate::rtw88::dma_stop::HIMR {
            self.write32(register, 0)?;
            if self.read32(register)? != 0 {
                return Err(Error::Prerequisite);
            }
        }
        Ok(())
    }
    /// Re-arm every RX buffer descriptor (`rtw_pci_init_rx_ring` layout:
    /// buffer size, then the retained buffer's DMA address). The device may
    /// have consumed slots the host never reaped; Linux drops those frames
    /// on `rtw_pci_dma_release` and so does this reset.
    fn rearm_rx(&mut self) -> Result<(), Error> {
        let gate = self.packet_gate.clone().ok_or(Error::State)?;
        gate.invoke(|| {
            crate::rtw88::pci_park::invoke(&self.cap, || {
                self.command(true)?;
                let ring = self.rx.as_ref().ok_or(Error::State)?;
                if self.buffers.len() != RX_DEPTH {
                    return Err(Error::State);
                }
                for (slot, buffer) in self.buffers.iter().enumerate() {
                    let address = dma_address(buffer, RX_BYTES)?;
                    buffer.sync(0, RX_BYTES);
                    // SAFETY: the retained RX BD array covers RX_DEPTH aligned
                    // 8-byte entries; this exact owner is the single CPU writer.
                    unsafe {
                        ring.cpu_mut_ptr_at::<u32>((slot * 8) as u64)
                            .write_volatile((RX_BYTES as u32).to_le());
                        ring.cpu_mut_ptr_at::<u32>((slot * 8 + 4) as u64)
                            .write_volatile(address.to_le());
                    }
                }
                ring.sync(0, RX_DEPTH * 8);
                super::barrier();
                Ok(())
            })
            .map_err(|_| Error::Access)?
        })
    }
    /// `rtw_pci_stop`: interrupts masked, then `rtw_pci_dma_release` ->
    /// `rtw_pci_reset_buf_desc`. Only a quiet owner may halt: no pending
    /// H2C/mailbox command, no retune, every TX ring retired. PCI BME, CR
    /// and every retained mapping are unchanged; `hci_restart` reverses it.
    pub(super) fn halt_packets(&mut self) -> Result<(), Error> {
        if !matches!(self.state, State::Packets | State::Swap)
            || self.command_ring.pending()
            || self.mailbox_pending
            || self.retune.is_some()
            || self.tracking_maintenance
            || !self.packet.as_ref().is_some_and(|core| core.ready())
        {
            return Err(Error::State);
        }
        let result = (|| {
            let mut core = self.packet.take().ok_or(Error::State)?;
            let halted = core.halt(|r| Port::index(self, r));
            self.packet = Some(core);
            halted.map_err(|_| Error::State)?;
            self.mask_interrupts()?;
            self.reset_buf_desc()?;
            self.halted_from = Some(self.state);
            self.state = State::Halted;
            Ok(())
        })();
        if result.is_err() {
            self.state = State::Terminal;
        }
        result
    }
    /// `rtw_pci_setup` (`rtw_pci_reset_trx_ring` + `rtw_pci_dma_reset`) and
    /// `rtw_pci_start`: re-arm RX, reset every ring pointer and the RX tag,
    /// then return to the state the owner was halted from. NARF has no IRQ
    /// line (`rtw_pci_enable_interrupt` is replaced by polling), so the
    /// HIMRs stay zero.
    pub(super) fn restart_packets(&mut self) -> Result<(), Error> {
        let Some(previous) = self.halted_from.filter(|_| self.state == State::Halted) else {
            return Err(Error::State);
        };
        let result = (|| {
            self.rearm_rx()?;
            self.reset_buf_desc()?;
            let ctrl = self.read32(PCI_CTRL)?;
            if ctrl == u32::MAX {
                return Err(Error::Gone);
            }
            self.write32(PCI_CTRL, ctrl | DMA_RESET)?;
            self.mask_interrupts()?;
            let mut core = self.packet.take().ok_or(Error::State)?;
            let restarted = core
                .reset_indices()
                .and_then(|()| core.restart(|r| Port::index(self, r)));
            self.packet = Some(core);
            restarted.map_err(|_| Error::State)?;
            self.halted_from = None;
            self.state = previous;
            Ok(())
        })();
        if result.is_err() {
            self.state = State::Terminal;
        }
        result
    }
}
/// `REG_RXPKT_NUM` `BIT_RW_RELEASE` | `BIT_RXDMA_IDLE` (`rtw_wow_rx_dma_stop`).
const RXPKT_NUM: u16 = 0x0284;
const RX_RELEASED_IDLE: u32 = 1 << 18 | 1 << 17;
impl Native {
    /// `wow.c::rtw_wow_swap_fw` precondition on the live station owner.
    /// From `Packets`: no pending H2C/mailbox command, no retune or tracking
    /// maintenance, a ready packet core whose every TX ring retired with the
    /// MAC queue pages free (`retune_quiet`), and RX DMA released and idle
    /// (`rtw_wow_stop_trx` ran; NARF refuses a swap under live RX DMA where
    /// Linux only logs). The window keeps BME/CR and every mapping; packet
    /// producers stay closed (`transmit_allowed`) until `end_swap`. Inside
    /// the window (resume restores the normal image) a quiet re-claim is
    /// accepted unchanged.
    pub(super) fn enter_swap(&mut self) -> Result<(), Error> {
        if self.command_ring.pending() || self.mailbox_pending {
            return Err(Error::State);
        }
        match self.state {
            State::Swap => return Ok(()),
            State::Packets => {}
            _ => return Err(Error::State),
        }
        if self.retune.is_some()
            || self.tracking_maintenance
            || !self.packet.as_ref().is_some_and(|core| core.ready())
        {
            return Err(Error::State);
        }
        if !self.retune_quiet()? {
            return Err(Error::State);
        }
        let rx = self.read32(RXPKT_NUM)?;
        if rx == u32::MAX {
            return Err(Error::Gone);
        }
        if rx & RX_RELEASED_IDLE != RX_RELEASED_IDLE {
            return Err(Error::State);
        }
        self.state = State::Swap;
        Ok(())
    }
    /// End of a swapped-image download (`Owner::run` -> `finish_dma`): the
    /// new firmware is running; unlike bring-up's `finish_dma` the owner is
    /// not parked and stays in the swap window.
    pub(super) fn complete_swap(&mut self) -> Result<(), Error> {
        if self.state != State::Swap || self.command_ring.pending() {
            self.state = State::Terminal;
            return Err(Error::State);
        }
        // Prove BME/MEM/INTx are still exactly the live packet setting.
        self.read32(PCI_CTRL).and_then(|v| {
            if v == u32::MAX {
                Err(Error::Gone)
            } else {
                Ok(())
            }
        })?;
        // mac.c::__rtw_download_firmware tail: `h2c.last_box_num = 0` and
        // `h2c.seq = 0` for every image download, the WoW swap included.
        // The swapped image's general/phydm info then carries 0/1 and the
        // running counter continues from there.
        self.mailbox_cursor = 0;
        self.tracking_sequence = 0;
        Ok(())
    }
    /// `rtw_wow_resume_trx` done: close the swap window and readmit the
    /// packet core that `restart_packets` reset (or never halted).
    pub(super) fn leave_swap(&mut self) -> Result<(), Error> {
        if self.state != State::Swap
            || self.command_ring.pending()
            || self.mailbox_pending
            || !self.packet.as_ref().is_some_and(|core| core.ready())
        {
            self.state = State::Terminal;
            return Err(Error::State);
        }
        self.state = State::Packets;
        Ok(())
    }
}
