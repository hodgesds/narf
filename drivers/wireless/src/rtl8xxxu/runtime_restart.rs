// SPDX-License-Identifier: GPL-2.0-or-later
//! A cold NIC restart after the retained radio proved USB/MAC retirement.
//! Linux rtl8xxxu/8188e.c::rtl8188eu_power_off and core.c::flush_fifo.
//! This never clears a failed EP0 owner or releases its physical USB claim.
use super::*;

struct Restart<'a, I: ControlIo> {
    owner: &'a Owner<I>,
    complete: bool,
}
impl<I: ControlIo> Drop for Restart<'_, I> {
    fn drop(&mut self) {
        if !self.complete {
            self.owner.runtime_failed(Error::Cancelled);
        }
    }
}

impl<I: ControlIo> Owner<I> {
    /// The one Receiver remains claimed. ReceiveStopped is published only
    /// after real endpoint Stop/SetDeq; source loss or uncertainty is terminal.
    pub(in crate::rtl8xxxu) async fn restart_stopped(&self) -> Result<(), Error> {
        if self.status().stage != Stage::ReceiveStopped
            || !self.runtime_taken.load(Ordering::Acquire)
        {
            return Err(Error::RuntimeState);
        }
        let expected = (
            self.factory().ok_or(Error::RuntimeState)?,
            self.endpoints().ok_or(Error::RuntimeState)?,
        );
        let image = self
            .runtime_image
            .lock()
            .clone()
            .ok_or(Error::RuntimeState)?;
        let executable = self.executable().ok_or(Error::RuntimeState)?;
        let actual = Executable::new(&image, None, false);
        if actual.digest != executable.digest {
            return Err(Error::InvalidImage);
        }
        executable.invoke(|| ())?;
        let mut attempt = Restart {
            owner: self,
            complete: false,
        };
        self.stage(Stage::Restarting);
        let result = executable
            .fence(async {
                self.power_off_stopped().await?;
                self.run_device_expected(
                    &image,
                    narf_time::Deadline::after_ms(30_000),
                    Some(expected),
                )
                .await
                .map(|_| ())
            })
            .await;
        attempt.complete = true;
        if let Err(error) = result {
            self.runtime_failed(error);
        }
        result
    }

    async fn update8(&self, reg: u16, clear: u8, set: u8) -> Result<(), Error> {
        let value = (self.read8(reg).await? & !clear) | set;
        self.write8(reg, value).await?;
        if self.read8(reg).await? != value {
            return Err(Error::RuntimeState);
        }
        Ok(())
    }
    async fn power_off_stopped(&self) -> Result<(), Error> {
        if self.read16(REG_CR).await? & 0xc0 != 0 {
            return Err(Error::RuntimeState);
        }
        // The radio requested this mode while its old receive TD still ran.
        // Idle is a current-transfer receipt, not proof of an empty RX FIFO.
        let rx = self.read32(0x284).await?;
        if rx & ((1 << 18) | (1 << 17)) != (1 << 18) | (1 << 17) {
            return Err(Error::RuntimeState);
        }
        self.write8(0x522, 0xff).await?;
        // Source flush_fifo: retire TX allocation before any cold reprogram.
        self.write16(0x214, 0).await?;
        self.write32(0x200, 1 << 31).await?;
        self.delay_us(2_000).await;
        if self.read16(0x214).await? != 0 || self.read32(0x200).await? & !(1 << 31) != 0 {
            return Err(Error::RuntimeState);
        }
        self.update8(0x4ec, 2, 0).await?; // TX report timer.
        self.write8(0x1f, 0).await?; // RF disabled before MAC reset.
        if self.read8(0x1f).await? != 0 {
            return Err(Error::RuntimeState);
        }
        self.poll(0x5f8, u32::MAX, 0, 101, 10, Error::PowerTimeout)
            .await?;
        self.update8(REG_SYS_FUNC, 1, 0).await?;
        self.delay_us(2).await;
        let cr = (self.read16(REG_CR).await? | 0xff) & !(0xc0 | (1 << 9));
        self.write16(REG_CR, cr).await?;
        if self.read16(REG_CR).await? != cr {
            return Err(Error::RuntimeState);
        }
        self.update8(0x553, 0, 1 << 5).await?;
        if self.read8(REG_MCU_FW_DL).await? & MCU_RAM_SELECT != 0 {
            self.write8(REG_HMTFR + 3, 0x20).await?;
            for _ in 0..100 {
                if self.read16(REG_SYS_FUNC).await? & SYS_FUNC_CPU_ENABLE == 0 {
                    break;
                }
                self.delay_us(50).await;
            }
        }
        let cpu = self.read16(REG_SYS_FUNC).await? & !SYS_FUNC_CPU_ENABLE;
        self.write16(REG_SYS_FUNC, cpu).await?;
        if self.read16(REG_SYS_FUNC).await? & SYS_FUNC_CPU_ENABLE != 0 {
            return Err(Error::RuntimeState);
        }
        self.write8(REG_MCU_FW_DL, 0).await?;
        if self.read8(REG_MCU_FW_DL).await? & (MCU_FW_DL_READY | 0xc0) != 0 {
            return Err(Error::RuntimeState);
        }
        self.update8(0x194, 1, 0).await?;
        self.update8(0x1f, 1, 0).await?;
        self.update8(REG_LPLDO_CTRL, 0, 1 << 4).await?;
        // RTL8188EU pwrseq.h::RTL8188E_TRANS_ACT_TO_CARDEMU:
        // APS_FSMCO[9] asks the hardware FSM to turn MAC off. Its terminal
        // self-clear, after exact EP0 publication, retires MAC FIFO ownership.
        // RF/LDO sleep or the MCU-only wrapper reset is not this receipt.
        let off = self.read8(REG_APS_FSMCO + 1).await? | 2;
        self.write8(REG_APS_FSMCO + 1, off).await?;
        self.poll(REG_APS_FSMCO, 1 << 9, 0, 101, 10, Error::PowerTimeout)
            .await?;
        let xtal = self.read32(REG_AFE_XTAL_CTRL).await? | (1 << 23);
        self.write32(REG_AFE_XTAL_CTRL, xtal).await?;
        let aps = (self.read16(REG_APS_FSMCO).await? & !(1 << 12)) | (1 << 11);
        self.write16(REG_APS_FSMCO, aps).await?;
        if self.read16(REG_APS_FSMCO).await? & (3 << 11) != 1 << 11 {
            return Err(Error::RuntimeState);
        }
        self.write8(REG_APS_FSMCO + 3, 0).await?;
        self.update8(0x41, 1 << 4, 0).await?;
        self.update8(0xfe10, 0, 1 << 4).await?;
        // Actual MCU I/O-wrapper reset is part of card-off, not a host epoch.
        self.update8(0x1d, 1 << 3, 0).await?;
        self.update8(0x1d, 0, 1 << 3).await?;
        let gpio = self.read8(0x44).await?;
        self.write8(0x45, gpio).await?;
        self.write8(0x46, 0xff).await?;
        let gpio = self.read8(0x42).await?;
        self.write8(0x42, gpio << 4).await?;
        self.update8(0x43, 0, 0x0f).await?;
        self.write32(0x64, 0x0008_0808).await?;
        self.write8(0x1c, 0).await?;
        self.write32(0x40, 0).await?;
        Ok(())
    }
}
