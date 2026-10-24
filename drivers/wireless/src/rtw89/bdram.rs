// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! AX internal BD-RAM/index preparation. No system-memory ring is published.
//! Linux pci.c::{ctrl_dma_all,poll_dma_all_idle,clr_idx_all_ax,
//! reset_trx_rings,rst_bdram_ax,ctrl_txdma_ch_ax}, kept DMA-disabled here.
use super::{
    dma::{addr_set_for_chip, TXCH_NUM},
    mac::ChipId,
    power::{Error, Io},
};

const INIT: u32 = 0x1000;
const STOP1: u32 = 0x1010;
const CLEAR1: u32 = 0x1014;
const BUSY1: u32 = 0x101c;
const WPDMA: u32 = 1 << 19;
const RESET: u32 = 1 << 3;
const INDEX_MASK: u32 = 0x0fff_0fff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    New,
    Preparing,
    Ready,
}

#[derive(Debug)]
pub struct Bdram {
    state: State,
}
impl Default for Bdram {
    fn default() -> Self {
        Self { state: State::New }
    }
}

#[derive(Clone, Copy)]
struct Profile {
    dual: bool,
    hci_mask: u32,
    io_stop_address: u32,
    io_stop_mask: u32,
    tx_mask: u32,
    tx_stop2: u32,
    tx_busy2: u32,
    tx_clear2: u32,
    rx_busy: u32,
    rx_clear: u32,
    wp_select: u32,
}
impl Profile {
    fn for_chip(chip: ChipId) -> Result<Self, Error> {
        let dual = match chip {
            ChipId::Rtl8852A | ChipId::Rtl8852C => true,
            ChipId::Rtl8852B | ChipId::Rtl8851B => false,
            ChipId::Rtl8922A => return Err(Error::Unsupported),
        };
        let v1 = chip == ChipId::Rtl8852C;
        Ok(Self {
            dual,
            hci_mask: if v1 {
                (1 << 15) | (1 << 7)
            } else {
                (1 << 13) | (1 << 11)
            },
            io_stop_address: if v1 { INIT } else { STOP1 },
            io_stop_mask: if v1 { 1 << 17 } else { 1 << 20 },
            tx_mask: if dual { 0x7ff00 } else { 0x70f00 },
            tx_stop2: if v1 {
                0x11c0
            } else if dual {
                0x1310
            } else {
                0
            },
            tx_busy2: if v1 {
                0x11c8
            } else if dual {
                0x131c
            } else {
                0
            },
            tx_clear2: if v1 {
                0x11c4
            } else if dual {
                0x1314
            } else {
                0
            },
            rx_busy: if v1 { 0x1208 } else { BUSY1 },
            rx_clear: if v1 { 0x1200 } else { 0x1018 },
            wp_select: if v1 { 0x1334 } else { 0 },
        })
    }
    fn channel(self, channel: usize) -> bool {
        self.dual || matches!(channel, 0..=3 | 8 | 9 | 12)
    }
    fn partition(self, channel: usize) -> u32 {
        let (start, max, min) = if self.dual {
            (
                channel as u32 * 5,
                if channel == 12 { 4 } else { 5 },
                if channel < 8 { 2 } else { 1 },
            )
        } else {
            match channel {
                0..=3 => (channel as u32 * 5, 5, 2),
                8 => (20, 4, 1),
                9 => (24, 4, 1),
                12 => (28, 4, 1),
                _ => unreachable!("unsupported channels are skipped before partition access"),
            }
        };
        start | (max << 8) | (min << 16)
    }
}

struct Access<'a, I>(&'a mut I);
impl<I: Io> Access<'_, I> {
    fn read(&mut self, address: u32) -> Result<u32, Error> {
        match self.0.read32(address)? {
            u32::MAX => Err(Error::Gone),
            value => Ok(value),
        }
    }
    fn modify(&mut self, address: u32, clear: u32, set: u32) -> Result<(), Error> {
        let value = self.read(address)?;
        self.0.write32(address, (value & !clear) | set)
    }
    fn expect(&mut self, address: u32, mask: u32, expected: u32) -> Result<(), Error> {
        if self.read(address)? & mask == expected {
            Ok(())
        } else {
            Err(Error::Access)
        }
    }
    async fn poll_clear(&mut self, address: u32, mask: u32, interval: u64) -> Result<(), Error> {
        let start = self.0.now_us();
        loop {
            if self.read(address)? & mask == 0 {
                return Ok(());
            }
            if self.0.now_us().saturating_sub(start) >= 100 {
                return Err(Error::Timeout);
            }
            self.0.delay_us(interval).await;
        }
    }
}

impl Bdram {
    pub fn state(&self) -> State {
        self.state
    }
    pub fn terminal() -> Self {
        Self {
            state: State::Preparing,
        }
    }

    /// # Safety
    /// Caller exclusively owns a powered exact AX device and current register
    /// authority, with PCI BME verified off, independently fenced old DMA and
    /// no concurrent producer, IRQ, PHY, power or reset operation. This owner
    /// does not establish a DMA reclamation proof. A replacement requires an
    /// independently verified device reset. No IRQ-disabling guard may span await.
    pub async unsafe fn prepare(&mut self, io: &mut impl Io, chip: ChipId) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        let profile = Profile::for_chip(chip)?;
        self.state = State::Preparing;
        let mut a = Access(io);
        a.modify(STOP1, 0, WPDMA)?;
        // Linux ctrl_dma_all(false): stop host I/O before disabling HCI.
        a.modify(profile.io_stop_address, 0, profile.io_stop_mask)?;
        a.modify(INIT, profile.hci_mask, 0)?;
        a.poll_clear(BUSY1, profile.tx_mask, 10).await?;
        if profile.tx_busy2 != 0 {
            a.poll_clear(profile.tx_busy2, 3, 10).await?;
        }
        a.poll_clear(profile.rx_busy, 3, 10).await?;
        a.modify(CLEAR1, 0, profile.tx_mask >> 8)?;
        if profile.tx_clear2 != 0 {
            a.modify(profile.tx_clear2, 0, 3)?;
        }
        a.modify(profile.rx_clear, 0, 3)?;

        let registers = addr_set_for_chip(chip);
        // Only the internal partition subset of reset_trx_rings is applied.
        // Ring base/count publication belongs to the later DMA owner.
        for channel in 0..TXCH_NUM {
            if !profile.channel(channel) {
                continue;
            }
            let address = registers.tx[channel].bdram as u32;
            let value = profile.partition(channel);
            a.0.write32(address, value)?;
            a.expect(address, u32::MAX, value)?;
        }
        if profile.wp_select != 0 {
            for offset in (0u32..16).step_by(4) {
                let value =
                    offset | ((offset + 1) << 8) | ((offset + 2) << 16) | ((offset + 3) << 24);
                a.0.write32(profile.wp_select + offset, value)?;
                a.expect(profile.wp_select + offset, u32::MAX, value)?;
            }
        }
        a.modify(INIT, 0, RESET)?;
        a.poll_clear(INIT, RESET, 1).await?;
        a.modify(STOP1, 0, profile.tx_mask)?;
        if profile.tx_stop2 != 0 {
            a.modify(profile.tx_stop2, 0, 3)?;
        }

        for channel in 0..TXCH_NUM {
            if profile.channel(channel) {
                a.expect(registers.tx[channel].idx as u32, INDEX_MASK, 0)?;
            }
        }
        for ring in &registers.rx {
            a.expect(ring.idx as u32, INDEX_MASK, 0)?;
        }
        a.expect(
            profile.io_stop_address,
            profile.io_stop_mask,
            profile.io_stop_mask,
        )?;
        a.expect(INIT, profile.hci_mask | RESET, 0)?;
        a.expect(STOP1, WPDMA | profile.tx_mask, WPDMA | profile.tx_mask)?;
        if profile.tx_stop2 != 0 {
            a.expect(profile.tx_stop2, 3, 3)?;
        }
        self.state = State::Ready;
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "bdram/tests.rs"]
mod tests;
