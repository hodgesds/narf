// SPDX-License-Identifier: GPL-2.0-or-later
//! Mounted under prepare: AE adopts original calibrated cold history and
//! publishes only retained inactive source-linked rings. No LLT/table replay.
use super::{
    extent, Chip, Error, Memory, Prepared, RX_BASE, RX_BUFFER, RX_BYTES, TX_BASES, TX_BYTES,
};
use crate::rtlwifi::{
    firmware_transport::Io,
    rtl8723ae::{self, phy, station_owner::State},
};
use alloc::boxed::Box;
impl<I: Io, M: Memory> Prepared<I, M> {
    pub(in crate::rtlwifi) fn adopt_rtl8723ae(&mut self, state: Box<State>) -> Result<(), Error> {
        if self.chip != Chip::Rtl8723ae
            || self.phase != super::Phase::Allocated
            || self.ae8723.is_some()
        {
            return Err(Error::State);
        }
        self.ae8723 = Some(state);
        Ok(())
    }
    pub(super) async fn prepare_rtl8723ae_rings(&mut self) -> Result<(), Error> {
        let state = self.ae8723.as_mut().ok_or(Error::State)?;
        let program = state.program.clone();
        let op = state.grant.permission().operating();
        let domain = program.prepared().current_domain()?;
        if program.grant_for(&domain)? != state.grant {
            return Err(Error::State);
        }
        let binding = program.prepared();
        if op.width != rtl8723ae::envelope::Width::W20
            || self.io.read8(0x100)? & 0xcf != 0
            || self.io.read32(rtl8723ae::irq::MASK0)? != 0
            || self.io.read32(rtl8723ae::irq::MASK1)? != 0
            || self.io.read8(0x680)? != 0
        {
            return Err(Error::Readback);
        }
        let live = phy::get_rf(&self.io, phy::Path::A, 0x18, phy::RFREG_OFFSET_MASK).await?;
        if live & 0xfff != 0x400 | u32::from(op.channel)
            || self.io.read8(0x603)? & 4 == 0
            || phy::get_bb(&self.io, 0x800, 1)? != 0
            || phy::get_bb(&self.io, 0x900, 1)? != 0
            || phy::get_bb(&self.io, 0x884, 1 << 10)? != 1
        {
            return Err(Error::Readback);
        }
        for (index, expected) in binding.factory().mac.iter().copied().enumerate() {
            if self.io.read8(rtl8723ae::mac::REG_MACID + index as u16)? != expected {
                return Err(Error::Readback);
            }
        }
        let plan = program.plan(state.grant)?;
        state.power.program(&self.io, &plan)?;
        plan.verify(&self.io)?;
        let receive = self.io.read32(rtl8723ae::mac::REG_RCR)?;
        let bcn = self.io.read8(0x550)?;
        if receive != binding.receive_config() || bcn != 0x1f {
            return Err(Error::Readback);
        }
        state.receive = Some(receive);
        state.bcn = Some(bcn);
        // This is BEFORE the first possibly accepted base write. The shared
        // regular storage already owns self; all failures retain every page.
        self.published = true;
        for (address, ring) in TX_BASES.iter().zip(&self.tx) {
            let base = extent(ring, self.depth * TX_BYTES, 256)?;
            self.io.write32(*address, base)?;
            if self.io.read32(*address)? != base {
                return Err(Error::Readback);
            }
        }
        let base = extent(
            self.receive.as_ref().ok_or(Error::State)?,
            self.depth * RX_BYTES,
            256,
        )?;
        self.io.write32(RX_BASE, base)?;
        if self.io.read32(RX_BASE)? != base
            || self.buffers.iter().any(|b| b.len() < RX_BUFFER)
            || self.io.read8(0x100)? & 0xcf != 0
            || self.io.read8(0x680)? != 0
            || self.io.read32(rtl8723ae::irq::MASK0)? != 0
            || self.io.read32(rtl8723ae::irq::MASK1)? != 0
        {
            return Err(Error::Readback);
        }
        // No Native/MLME readiness is minted: generic station_grant is None.
        Ok(())
    }
}
