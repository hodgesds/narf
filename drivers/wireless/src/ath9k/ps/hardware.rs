// SPDX-License-Identifier: GPL-2.0-or-later
//! Source power transitions over raw current-cap MMIO. This interface is
//! deliberately below Native::access: a wake cannot recurse through a read
//! that already assumes AWAKE. Callers retain source +PCI invocations.
use crate::ath9k::packet::Error;
pub(in crate::ath9k) trait Raw {
    fn read(&self, register: u64) -> Result<u32, Error>;
    fn write(&self, register: u64, value: u32) -> Result<(), Error>;
    fn delay(&self, us: u64);
    /// Native uses scheduler's bounded responsive primitive; model virtual
    /// time exercises the same state predicates without a host receipt.
    fn wait(&self, register: u64, mask: u32, expected: u32, budget_us: u64) -> Result<(), Error>;
}
fn write(io: &impl Raw, register: u64, value: u32) -> Result<(), Error> {
    io.write(register, value)?;
    if io.read(register)? != value {
        return Err(Error::Descriptor);
    }
    Ok(())
}
fn modify(io: &impl Raw, register: u64, clear: u32, set: u32) -> Result<(), Error> {
    write(io, register, (io.read(register)? & !clear) | set)
}
pub(in crate::ath9k) fn awake(io: &impl Raw) -> Result<(), Error> {
    let status = io.read(0x7044)? & 15;
    // SHUTDOWN would require a full reset/PLL and key/DMA retirement. Never
    // invent live association preservation by doing that inside packet I/O.
    if !matches!(status, 2 | 4) {
        return Err(Error::State);
    }
    modify(io, 0x704c, 0, 1)?;
    io.delay(50);
    io.wait(0x7044, 15, 2, 2000)?;
    modify(io, 0x8004, 0x40000, 0)
}
pub(in crate::ath9k) fn network_sleep(io: &impl Raw) -> Result<(), Error> {
    if io.read(0x7044)? & 15 != 2
        || io.read(0x840)? & 0x3ff != 0
        || io.read(0x24)? & 1 == 0
        || io.read(0x8240)? & 0x31 != 0x31
        || io.read(0xb8)? & 0x10 == 0
        || io.read(0xa0)? & 0x10000000 == 0
        || io.read(0x403c)? & 2 == 0
    {
        return Err(Error::State);
    }
    for queue in 0..10 {
        if io.read(0xa00 + queue * 4)? & 3 != 0 {
            return Err(Error::State);
        }
    }
    modify(io, 0x8048, 0, 0x02000020)?;
    // ath9k_hw_setrxabort: actual RX state must be0, not merely CR_RXE.
    io.wait(0x806c, 0x01f00000, 0, 2000)?;
    modify(io, 0x8004, 0, 0x40000)?;
    write(io, 0x704c, 2)?; // AR_RTC_FORCE_WAKE_ON_INT, no ForceWake.
                           // Prove actual sleep as well as the request; ignored writes are not a
                           // completed power transition. Everything remains mapped while asleep.
    io.wait(0x7044, 15, 4, 2000)
}
