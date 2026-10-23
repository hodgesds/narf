// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Owned 22000 APM/NIC preparation before context-v1 DMA publication.
//! Linux pcie/gen1_2/trans{,-gen2}.c and mvm/ops.c; no device rings here.
use super::{gen2_profile::Profile, regs};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Access,
    Gone,
    Timeout,
    Persistence,
    Terminal,
    RadioDisabled,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    New,
    Preparing,
    Prepared,
}
#[derive(Debug)]
pub struct Owner {
    phase: Phase,
}
impl Default for Owner {
    fn default() -> Self {
        Self { phase: Phase::New }
    }
}
pub trait Io {
    fn read(&mut self, register: u32) -> Result<u32, Error>;
    fn write(&mut self, register: u32, value: u32) -> Result<(), Error>;
    fn now_us(&self) -> u64;
    async fn delay_us(&mut self, us: u64);
}
struct Registers<'a, I>(&'a mut I);
impl<I: Io> Registers<'_, I> {
    fn read(&mut self, r: u32) -> Result<u32, Error> {
        let v = self.0.read(r)?;
        if v == u32::MAX {
            Err(Error::Gone)
        } else {
            Ok(v)
        }
    }
    fn modify(&mut self, r: u32, mask: u32, value: u32) -> Result<(), Error> {
        let old = self.read(r)?;
        self.0.write(r, (old & !mask) | (value & mask))
    }
    fn set(&mut self, r: u32, bits: u32) -> Result<(), Error> {
        self.modify(r, bits, bits)
    }
    fn clear(&mut self, r: u32, bits: u32) -> Result<(), Error> {
        self.modify(r, bits, 0)
    }
    fn prph_read(&mut self, address: u32) -> Result<u32, Error> {
        self.0
            .write(regs::HBUS_TARG_PRPH_RADDR, (address & 0xfffff) | (3 << 24))?;
        self.read(regs::HBUS_TARG_PRPH_RDAT)
    }
    fn prph_write(&mut self, address: u32, value: u32) -> Result<(), Error> {
        self.0
            .write(regs::HBUS_TARG_PRPH_WADDR, (address & 0xfffff) | (3 << 24))?;
        self.0.write(regs::HBUS_TARG_PRPH_WDAT, value)
    }
    fn prph_modify(&mut self, address: u32, mask: u32, value: u32) -> Result<(), Error> {
        let old = self.prph_read(address)?;
        self.prph_write(address, (old & !mask) | (value & mask))
    }
    async fn poll(&mut self, r: u32, mask: u32, value: u32, budget_us: u64) -> Result<(), Error> {
        let begin = self.0.now_us();
        loop {
            if self.read(r)? & mask == value {
                return Ok(());
            }
            if self.0.now_us().saturating_sub(begin) >= budget_us {
                return Err(Error::Timeout);
            }
            self.0.delay_us(1).await;
        }
    }
    async fn try_ownership(&mut self) -> Result<(), Error> {
        self.set(0, 1 << 22)?;
        self.poll(0, 1 << 22, 1 << 22, 50).await?;
        self.set(0x88, 1 << 5)
    }
    async fn ownership(&mut self) -> Result<(), Error> {
        match self.try_ownership().await {
            Ok(()) => return Ok(()),
            Err(Error::Timeout) => {}
            Err(e) => return Err(e),
        }
        // No ME/SAP transport is exposed by this host. Never steal an owned
        // device: only Linux's bounded WAKE_ME handshake can grant it back.
        self.set(0x250, 1 << 31)?;
        self.0.delay_us(2000).await;
        for _ in 0..10 {
            self.set(0, 1 << 27)?;
            let begin = self.0.now_us();
            loop {
                match self.try_ownership().await {
                    Ok(()) => return Ok(()),
                    Err(Error::Timeout) => {}
                    Err(e) => return Err(e),
                }
                self.0.delay_us(200).await;
                if self.0.now_us().saturating_sub(begin) >= 150000 {
                    break;
                }
            }
            self.0.delay_us(25000).await;
        }
        Err(Error::Timeout)
    }
    async fn reset(&mut self) -> Result<(), Error> {
        self.set(0x20, 1 << 7)?;
        self.0.delay_us(6000).await;
        self.ownership().await
    }
    async fn activate(&mut self, discrete: bool) -> Result<(), Error> {
        if discrete {
            self.0.delay_us(2000).await;
        }
        // Keep MAC_ACCESS_REQ asserted after the INIT_DONE clock handshake,
        // since all later PRPH accesses run under the same serialized owner.
        self.set(0x24, (1 << 2) | (1 << 3))?;
        self.poll(0x24, 1 | (1 << 4), 1, 25000).await?;
        if discrete {
            self.0.delay_us(200).await;
        }
        Ok(())
    }
}
impl Owner {
    pub fn phase(&self) -> Phase {
        self.phase
    }
    /// # Safety
    /// Caller exclusively owns the exact profile's 22000 PCI function and
    /// current MMIO authority, has parked and verified PCI bus mastering,
    /// and keeps any preexisting DMA memory retained through reset.
    /// This helper releases no DMA memory. No live ring/firmware/IRQ producer
    /// may race preparation. A fresh owner
    /// is permitted only after the same conditions have been re-established.
    pub async unsafe fn prepare(
        &mut self,
        io: &mut impl Io,
        profile: Profile,
        hw_rev: u32,
        phy: u32,
    ) -> Result<(), Error> {
        if self.phase != Phase::New {
            return Err(Error::Terminal);
        }
        self.phase = Phase::Preparing;
        let mut r = Registers(io);
        r.ownership().await?;
        // Persistence may only be cleared if firmware has not write-protected
        // that register; a protected/inaccessible ME lifecycle stays terminal.
        let hpm = r.prph_read(0xa03440)?;
        if hpm & (1 << 12) != 0 {
            if r.prph_read(0xa04d00)? & (1 << 12) != 0 {
                return Err(Error::Persistence);
            }
            r.prph_write(0xa03440, hpm & !(1 << 12))?;
        }
        r.reset().await?;
        if profile.integrated {
            r.activate(false).await?;
            r.prph_modify(0xa03458, 1 << 10, 1 << 10)?;
            r.0.delay_us(20).await;
            r.prph_modify(0xa03458, 3, 3)?;
            r.0.delay_us(20).await;
            r.prph_modify(0xa03458, 1 << 10, 0)?;
            r.reset().await?;
        }
        r.0.write(0x8, 0)?; // no interrupts before the retained vector exists
        r.0.write(0xc, u32::MAX)?;
        r.set(0x100, 1 << 23)?; // L1A_NO_L0S_RX
        r.set(0x240, 0xffff0000)?; // maximum FH wait threshold
        r.set(0, 1 << 19)?; // management wake
        r.set(0x3c, 2)?; // disable unstable PCIe L0s
        r.activate(!profile.integrated).await?;
        if r.read(0x24)? & (1 << 27) == 0 {
            return Err(Error::RadioDisabled);
        }
        // 22000 has no APMG unit. Set the MAC stepping and firmware-selected
        // RF type/step/dash, and explicitly clear obsolete SI/debug bits.
        let radio = ((phy & 3) << 10) | (((phy >> 2) & 3) << 14) | (((phy >> 4) & 3) << 12);
        r.modify(0, 0xff0f, hw_rev & 15 | radio)?;
        r.0.write(0x5c, 2)?; // clear stale SW RF-kill handshake
        r.0.write(0x5c, 4)?; // clear stale command-blocked handshake
        r.0.write(0xc, u32::MAX)?;
        r.set(0xa8, 0x800fffff)?; // command/RX shadow registers
        self.phase = Phase::Prepared;
        Ok(())
    }
    /// Linux's ROM latency workaround must precede UREG_CPU_INIT_RUN, after
    /// retained queue/context publication. It is separate from power policy.
    pub fn rom_ltr(io: &mut impl Io, profile: Profile) -> Result<(), Error> {
        let mut r = Registers(io);
        const VALUE: u32 = 0x88fa88fa; // request + usec scale2 +250, snoop/nonsnoop
        if profile.integrated {
            r.prph_write(0xa0348c, 0xf)?;
            r.prph_write(0xa03480, VALUE)
        } else {
            r.0.write(0xd4, VALUE)
        }
    }
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "gen2_prepare_tests.rs"]
mod tests;
