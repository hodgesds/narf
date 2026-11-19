// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Source RTL8922A SCC BB Tx/Rx paths and complete hal_reset bracket.
//! rtw8922a.c::bb_cfg_txrx_path/ctrl_trx_path/ctrl_{tx,rx}_path_tmac,
//! ::cfg_rx_nss_limit/hal_reset and mac_be.c::cfg_ppdu_status_be.
//! Programmed paths are not calibrated RF or ordinary RX/station readiness.
use super::{
    be_mailbox::Receipt,
    operating_channel_c::Band,
    rfk::{Error, Interface},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Config {
    tx: u8,
    rx: u8,
}
impl Config {
    pub(super) fn from_receipt(receipt: &Receipt) -> Result<Self, Error> {
        let (_, _, tx, rx, _) = receipt.topology();
        if !(1..=3).contains(&tx) || !(1..=3).contains(&rx) {
            return Err(Error::Policy);
        }
        Ok(Self { tx, rx })
    }
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "be_path_tests.rs"]
mod tests;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Busy,
    Programmed,
}
#[derive(Default)]
pub(super) struct Paths {
    state: State,
    config: Option<Config>,
}
struct Access<'a, I>(&'a mut I);
impl<I: Interface> Access<'_, I> {
    fn read(&mut self, address: u32) -> Result<u32, Error> {
        self.0.admit()?;
        let value = self.0.read32(address)?;
        if value == u32::MAX {
            return Err(super::power::Error::Gone.into());
        }
        Ok(value)
    }
    fn write(&mut self, address: u32, value: u32) -> Result<(), Error> {
        self.0.admit()?;
        self.0.write32(address, value)?;
        self.0.admit()
    }
    fn field(&mut self, address: u32, mask: u32, value: u32) -> Result<(), Error> {
        let old = self.read(address)?;
        self.write(
            address,
            (old & !mask) | ((value << mask.trailing_zeros()) & mask),
        )
    }
    fn bb(&mut self, address: u32, mask: u32, value: u32) -> Result<(), Error> {
        self.field(0x20000 + address, mask, value)
    }
    async fn delay(&mut self, us: u64) -> Result<(), Error> {
        self.0.admit()?;
        self.0.delay_us(us).await;
        self.0.admit()
    }
    fn ppdu(&mut self, enabled: bool) -> Result<(), Error> {
        if enabled {
            self.field(0x9c30, 0xff, 3)?;
            self.write(0x11440, 0x6d)
        } else {
            self.field(0x11440, 1, 0)
        }
    }
    fn dfs(&mut self, enabled: bool) -> Result<(), Error> {
        self.bb(0x2800, 2, u32::from(enabled))?;
        self.bb(0x2900, 2, u32::from(enabled))
    }
    fn tssi(&mut self, enabled: bool) -> Result<(), Error> {
        self.bb(0xe610, 8, u32::from(!enabled))?;
        self.bb(0xe710, 8, u32::from(!enabled))
    }
    fn adc(&mut self, enabled: bool) -> Result<(), Error> {
        // Source path A then B each reads/modifies the shared8-bit field.
        for bit in [1, 2] {
            let current = (self.read(0x210fc)? >> 24) & 255;
            self.bb(
                0x10fc,
                0xff000000,
                if enabled {
                    current & !bit
                } else {
                    current | bit
                },
            )?;
        }
        Ok(())
    }
    async fn reset(&mut self, band: Band, enabled: bool) -> Result<(), Error> {
        if enabled {
            self.bb(0x704, 2, 1)?;
            if band == Band::Ghz2 {
                self.bb(0x520, 1, 0)?;
            }
            self.bb(0xc3c, 0x200, 0)
        } else {
            self.bb(0x520, 1, 1)?;
            self.bb(0xc3c, 0x200, 1)?;
            self.delay(1).await?;
            self.bb(0x704, 2, 0)
        }
    }
    fn nss(&mut self, rx: u8) -> Result<(), Error> {
        let nss = u32::from(rx == 3);
        for (address, mask, value) in [
            (0x418, 0x300, nss),
            (0x418, 0x600000, nss),
            (0x480, 0x3fc0, 4),
            (0x480, 0x1c000, nss),
            (0x480, 0x3800000, nss),
            (0x474, 0x1c, nss),
            (0x478, 0x1c000, nss),
            (0x478, 0xff000000, 4),
        ] {
            self.bb(address, mask, value)?;
        }
        Ok(())
    }
    fn tx(&mut self, tx: u8, iteration: u8) -> Result<(), Error> {
        self.bb(0x9a4, 0xe0000, 0)?;
        // Source PHY1 iteration returns here in non-DBCC. Its preceding
        // BB write is still to PHY0 because idx remapping requires DBCC.
        if iteration == 1 {
            return Ok(());
        }
        let words = match tx {
            1 => [
                0x21c82900, 0x00e4e431, 0x39390c49, 0x4e431240, 0x90c4900e, 0x00240393, 0x201c8200,
            ],
            2 => [
                0x21c04900, 0x00e4e032, 0x39380c89, 0x4e032240, 0x80c8900e, 0x00240393, 0x201c0400,
            ],
            3 => [
                0x21c86900, 0x00e4e433, 0x39390cc9, 0x4e433240, 0x90cc900e, 0x00240393, 0x201c8600,
            ],
            _ => return Err(Error::Policy),
        };
        for (index, value) in words.into_iter().enumerate() {
            self.write(0x11a00 + index as u32 * 4, value)?;
        }
        Ok(())
    }
    fn rx(&mut self, rx: u8) -> Result<(), Error> {
        self.bb(0x6b54, 15, 0)?;
        self.bb(0x6b54, 15, u32::from(rx))?;
        self.bb(0x6b50, 0x3c000, u32::from(rx))?;
        self.nss(rx)?;
        // Non-MLO source reset pulses both paths even for an RX-A/B profile.
        for address in [0xe60c, 0xe70c] {
            self.bb(address, 0x10000, 0)?;
            self.bb(address, 0x10000, 1)?;
        }
        Ok(())
    }
}
impl Paths {
    pub(super) fn state(&self) -> State {
        self.state
    }
    /// # Safety
    /// Actual original RTL8922A after selected BE tables/DM/NCTL/power trim,
    /// with the source cold SCC profile and actual GET_FEATURE topology.
    /// CMAC0 packets remain positively closed, MAC1 fully off, BB1 held.
    /// Interface enforces current device/full program/calibration/policy
    /// qualification inside each actual MMIO/analog operation and the source
    /// BE32 scheduler owner. No concurrent reset/IRQ/packet producer. Error or
    /// cancellation terminalizes the enclosing radio without freeing DMA.
    pub(super) async unsafe fn configure(
        &mut self,
        io: &mut impl Interface,
        config: Config,
        band: Band,
    ) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        self.state = State::Busy;
        self.config = None;
        io.admit()?;
        let saved = io.pause().await?;
        let mut a = Access(io);
        a.ppdu(false)?;
        a.dfs(false)?;
        a.tssi(false)?;
        a.adc(false)?;
        a.delay(40).await?;
        a.reset(band, false).await?;
        for iteration in 0..2 {
            a.tx(config.tx, iteration)?;
            a.rx(config.rx)?;
            a.nss(config.rx)?;
        }
        a.ppdu(true)?;
        a.adc(true)?;
        a.dfs(true)?;
        a.tssi(true)?;
        a.reset(band, true).await?;
        a.0.admit()?;
        a.0.resume(saved).await?;
        a.0.admit()?;
        self.config = Some(config);
        self.state = State::Programmed;
        Ok(())
    }
}
/// Retained source set_channel_help/hal_reset bracket, separate from initial
/// Tx/Rx path setup. An interrupted enter/exit cannot manufacture a new saved
/// scheduler token or resume from reconstructed metadata.
#[derive(Default)]
pub(super) struct Bracket {
    saved: Option<u32>,
    busy: bool,
}
impl Bracket {
    pub(super) async fn enter(&mut self, io: &mut impl Interface, band: Band) -> Result<(), Error> {
        if self.busy || self.saved.is_some() {
            return Err(Error::Terminal);
        }
        self.busy = true;
        io.admit()?;
        self.saved = Some(io.pause().await?);
        let mut a = Access(io);
        a.ppdu(false)?;
        a.dfs(false)?;
        a.tssi(false)?;
        a.adc(false)?;
        a.delay(40).await?;
        a.reset(band, false).await?;
        self.busy = false;
        Ok(())
    }
    pub(super) async fn exit(&mut self, io: &mut impl Interface, band: Band) -> Result<(), Error> {
        if self.busy {
            return Err(Error::Terminal);
        }
        let saved = self.saved.ok_or(Error::Terminal)?;
        self.busy = true;
        let mut a = Access(io);
        a.ppdu(true)?;
        a.adc(true)?;
        a.dfs(true)?;
        a.tssi(true)?;
        a.reset(band, true).await?;
        a.0.resume(saved).await?;
        a.0.admit()?;
        self.saved = None;
        self.busy = false;
        Ok(())
    }
}
