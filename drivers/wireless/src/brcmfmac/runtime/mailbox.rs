// SPDX-License-Identifier: GPL-2.0-or-later
//! PCIe2 mailbox interrupt service and host<->dongle mailbox data.
//!
//! Linux v7.2 `brcmfmac/pcie.c`: `brcmf_reginfo_default`/`brcmf_reginfo_64`
//! (selected by PCIe2 core revision >= 64 in `brcmf_pcie_probe`),
//! `brcmf_pcie_intr_disable`/`brcmf_pcie_intr_enable`,
//! `brcmf_pcie_quick_check_isr`, `brcmf_pcie_isr_thread`,
//! `brcmf_pcie_handle_mb_data`, `brcmf_pcie_send_mb_data` and
//! `brcmf_pcie_release_irq`. The vector handler (`brcmfmac/irq.rs`) only
//! raises [`Signal`]; every BAR access below runs in the owner's service.
use super::*;
use crate::brcmfmac::irq::Signal;
use alloc::sync::Arc;

/// `BRCMF_PCIE_PCIE2REG_{INTMASK,MAILBOXINT,MAILBOXMASK}`.
const INTMASK: u32 = 0x24;
const MAILBOXINT: u32 = 0x48;
const MAILBOXMASK: u32 = 0x4c;
/// `BRCMF_PCIE_64_PCIE2REG_{INTMASK,MAILBOXINT,MAILBOXMASK}`.
const INTMASK_64: u32 = 0xc14;
const MAILBOXINT_64: u32 = 0xc30;
const MAILBOXMASK_64: u32 = 0xc34;
/// `BRCMF_PCIE_MB_INT_FN0` (FN0_0 | FN0_1).
pub const MB_INT_FN0: u32 = 0x0300;
/// `BRCMF_PCIE_MB_INT_D2H_DB` (D2H0..3 DB0/DB1).
pub const MB_INT_D2H_DB: u32 = 0x00ff_0000;
/// `BRCMF_PCIE_64_MB_INT_D2H_DB` (D2H0..7 DB0/DB1).
pub const MB_INT_D2H_DB_64: u32 = 0x0000_ffff;

/// `BRCMF_D2H_DEV_*` dongle-to-host mailbox data.
pub const D2H_DEV_D3_ACK: u32 = 0x0000_0001;
pub const D2H_DEV_DS_ENTER_REQ: u32 = 0x0000_0002;
pub const D2H_DEV_DS_EXIT_NOTE: u32 = 0x0000_0004;
pub const D2H_DEV_FWHALT: u32 = 0x1000_0000;
/// `BRCMF_H2D_HOST_*` host-to-dongle mailbox data.
pub const H2D_HOST_D3_INFORM: u32 = 0x0000_0001;
pub const H2D_HOST_DS_ACK: u32 = 0x0000_0002;
pub const H2D_HOST_D0_INFORM_IN_USE: u32 = 0x0000_0008;
pub const H2D_HOST_D0_INFORM: u32 = 0x0000_0010;

/// `struct brcmf_pcie_reginfo` with backplane addresses of one PCIe2 core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reginfo {
    pub intmask: u32,
    pub mailboxint: u32,
    pub mailboxmask: u32,
    pub int_d2h_db: u32,
    pub int_fn0: u32,
}
impl Reginfo {
    pub const fn for_core(base: u32, revision: u8) -> Self {
        if revision >= 64 {
            Self {
                intmask: base + INTMASK_64,
                mailboxint: base + MAILBOXINT_64,
                mailboxmask: base + MAILBOXMASK_64,
                int_d2h_db: MB_INT_D2H_DB_64,
                int_fn0: 0,
            }
        } else {
            Self {
                intmask: base + INTMASK,
                mailboxint: base + MAILBOXINT,
                mailboxmask: base + MAILBOXMASK,
                int_d2h_db: MB_INT_D2H_DB,
                int_fn0: MB_INT_FN0,
            }
        }
    }
    /// `brcmf_pcie_intr_enable`'s mask value.
    pub const fn enabled(self) -> u32 {
        self.int_d2h_db | self.int_fn0
    }
}

/// Mailbox service state retained by the owner.
#[derive(Clone, Copy, Debug)]
pub(super) struct Mailbox {
    pub reg: Reginfo,
    pub htod: u32,
    pub dtoh: u32,
    /// `devinfo->mbdata_completed` for the outstanding D3_INFORM.
    pub d3_acked: bool,
    /// A D3_INFORM is outstanding: consume D2H mailbox data even without
    /// an FN0 status bit (rev >= 64 cores have `int_fn0 == 0`).
    pub awaiting: bool,
    /// Deep-sleep ACK deferred because a prior H2D mailbox word was pending.
    pub ds_ack: bool,
    /// Mailbox interrupt services that observed a nonzero status.
    pub services: u64,
}

/// Interrupt service counters exposed for diagnostics and fixtures.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InterruptStats {
    pub delivered: bool,
    pub services: u64,
    pub vectors: u64,
}

impl<B: Bus> Runtime<B> {
    pub(super) fn read_reg(&mut self, address: u32) -> Result<u32, Error> {
        let value = self.bus.read32(address).map_err(|_| Error::Access)?;
        if value == u32::MAX {
            // A function that fell off the bus reads all-ones.
            return Err(Error::Access);
        }
        Ok(value)
    }
    fn write_reg(&mut self, address: u32, value: u32) -> Result<(), Error> {
        self.bus.write32(address, value).map_err(|_| Error::Access)
    }
    fn read_tcm32(&mut self, address: u32) -> Result<u32, Error> {
        let mut bytes = [0; 4];
        self.bus.read_tcm(address, &mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
    /// `brcmf_pcie_intr_disable`.
    pub(super) fn intr_disable(&mut self) -> Result<(), Error> {
        let Some(mailbox) = self.mailbox else {
            return Ok(());
        };
        self.write_reg(mailbox.reg.mailboxmask, 0)
    }
    /// `brcmf_pcie_intr_enable`.
    pub(super) fn intr_enable(&mut self) -> Result<(), Error> {
        let Some(mailbox) = self.mailbox else {
            return Ok(());
        };
        self.write_reg(mailbox.reg.mailboxmask, mailbox.reg.enabled())
    }
    /// `brcmf_pcie_request_irq` (the mask is already clear from attach)
    /// followed by `brcmf_pcie_preinit`'s `brcmf_pcie_intr_enable`. A
    /// missing vector keeps polled service with the same mailbox mask.
    pub(super) fn start_interrupts(&mut self) -> Result<(), Error> {
        if self.mailbox.is_none() {
            return Ok(());
        }
        let signal = self.signal.clone();
        self.delivered = self.bus.arm_interrupts(&signal);
        self.intr_enable()
    }
    /// `brcmf_pcie_release_irq`: mask, free the vector, then clear any
    /// latched status. Safe to repeat.
    pub(super) fn stop_interrupts(&mut self) {
        let _ = self.intr_disable();
        if self.delivered {
            self.bus.disarm_interrupts();
            self.delivered = false;
        }
        if let Some(mailbox) = self.mailbox {
            if let Ok(status) = self.read_reg(mailbox.reg.mailboxint) {
                let _ = self.write_reg(mailbox.reg.mailboxint, status);
            }
        }
    }
    /// The owner's wake source and whether a vector actually delivers it.
    pub fn interrupt(&self) -> (Arc<Signal>, bool) {
        (self.signal.clone(), self.delivered)
    }
    pub fn interrupt_stats(&self) -> InterruptStats {
        InterruptStats {
            delivered: self.delivered,
            services: self.mailbox.map_or(0, |m| m.services),
            vectors: self.signal.count(),
        }
    }
    /// `brcmf_pcie_quick_check_isr` + `brcmf_pcie_isr_thread`, run at the
    /// start of every owner service (vector, fallback timer or poll).
    /// D2H doorbells need no separate action: the caller's ring service is
    /// `brcmf_proto_msgbuf_rx_trigger`.
    pub(super) fn service_mailbox(&mut self) -> Result<(), Error> {
        let Some(mailbox) = self.mailbox else {
            return Ok(());
        };
        let status = self.read_reg(mailbox.reg.mailboxint)?;
        if status != 0 {
            self.intr_disable()?;
            self.write_reg(mailbox.reg.mailboxint, status)?;
            if let Some(mailbox) = self.mailbox.as_mut() {
                mailbox.services = mailbox.services.saturating_add(1);
            }
        }
        if status & mailbox.reg.int_fn0 != 0 || mailbox.awaiting {
            self.handle_mb_data()?;
        }
        if self.mailbox.is_some_and(|m| m.ds_ack) {
            match self.try_send_mb_data(H2D_HOST_DS_ACK) {
                Ok(()) => self.mailbox.as_mut().unwrap().ds_ack = false,
                Err(Error::Busy) => {}
                Err(error) => return Err(error),
            }
        }
        if status != 0 && self.link_up() {
            self.intr_enable()?;
        }
        Ok(())
    }
    /// `brcmf_pcie_handle_mb_data`.
    fn handle_mb_data(&mut self) -> Result<(), Error> {
        let Some(mailbox) = self.mailbox else {
            return Ok(());
        };
        let value = self.read_tcm32(mailbox.dtoh)?;
        if value == 0 {
            return Ok(());
        }
        self.bus.write_tcm(mailbox.dtoh, &0u32.to_le_bytes())?;
        if value & D2H_DEV_DS_ENTER_REQ != 0 {
            match self.try_send_mb_data(H2D_HOST_DS_ACK) {
                Ok(()) => {}
                Err(Error::Busy) => self.mailbox.as_mut().unwrap().ds_ack = true,
                Err(error) => return Err(error),
            }
        }
        if value & D2H_DEV_D3_ACK != 0 {
            self.mailbox.as_mut().unwrap().d3_acked = true;
        }
        if value & D2H_DEV_FWHALT != 0 {
            // brcmf_fw_crashed: this firmware generation is terminal.
            return Err(Error::Failed);
        }
        Ok(())
    }
    /// One attempt of `brcmf_pcie_send_mb_data`: Linux sleeps 10 ms up to
    /// 100 times while a prior word is pending; callers here retry on
    /// `Busy` from their own bounded async loop.
    pub(super) fn try_send_mb_data(&mut self, value: u32) -> Result<(), Error> {
        let Some(mailbox) = self.mailbox else {
            return Err(Error::Protocol);
        };
        if self.read_tcm32(mailbox.htod)? != 0 {
            return Err(Error::Busy);
        }
        self.bus.write_tcm(mailbox.htod, &value.to_le_bytes())?;
        self.bus.ring_mailbox()
    }
}
