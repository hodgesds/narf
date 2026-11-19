// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8922A cold SCC DM prerequisites, with separately scoped native profiles.
//! Source phy_dm_init/phy_be.c callbacks/rtw8922a_bb_sethw and RFK PLL init.
//! N22P explicitly omits the powered-off MAC1 UL pair. N22W admits that exact
//! pair through its retained power-window owner; neither earns RadioReady.
use super::{
    efuse_be::BeFactory, mac_pre_init_8922a::HalChipVer, phy_operating, power, rfk::Error,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Field(u32, u32, u32),
    Write(u32, u32),
}
#[path = "phy_operating_be_program.rs"]
mod program;
#[cfg(any(test, feature = "kernel-test"))]
#[path = "phy_operating_be_tests.rs"]
mod tests;
/// Source disabled thermal protection/debug profile uses a constant80 for
/// statistics. Preserve its distinction from an actual RF-sensor observation;
/// neither factory PG thermal nor this fallback is a live RFK measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Thermal {
    DisabledByProfile,
    Measured(u8),
}
pub(super) trait Interface: phy_operating::Interface {
    async fn thermal(&mut self, path: u8) -> Result<Thermal, Error>;
    fn mac1_ul_power(&mut self) -> Result<(), Error> {
        Err(Error::Policy)
    }
}
/// rtw8922a_get_thermal in the source debug-disabled native profile. The
/// threshold is derived from the actual PCI quirk; trim is actual PHYcap.
/// A fallback is deliberately not represented as a measured80/sensor input.
pub(super) async fn source_thermal(
    io: &mut impl super::rfk::Interface,
    path: u8,
    threshold: u8,
    trim: [i8; 2],
) -> Result<Thermal, Error> {
    if path >= 2 {
        return Err(Error::Policy);
    }
    io.admit()?;
    if threshold == 0 {
        return Ok(Thermal::DisabledByProfile);
    }
    for value in [1, 0, 1] {
        io.rf_write(path, 0x42, 0x80000, value).await?;
    }
    io.delay_us(200).await;
    let raw = io.rf_read(path, 0x42, 0xff).await?;
    if raw > 255 {
        return Err(Error::Terminal);
    }
    let sample = (raw as i16 + i16::from(trim[usize::from(path)])).clamp(0, 255) as u8;
    io.admit()?;
    Ok(Thermal::Measured(sample))
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Busy,
    PartialMac1Off,
    CompleteMac1Restored,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Working {
    pub(super) crystal_default: u8,
    pub(super) crystal_actual: u8,
    pub(super) crystal_lower: u8,
    pub(super) crystal_upper: u8,
    pub(super) thermal: [Thermal; 2],
}
#[derive(Default)]
pub(super) struct Operating {
    state: State,
    working: Option<Working>,
}
struct Access<'a, I>(&'a mut I);
impl<I: Interface> Access<'_, I> {
    fn read(&mut self, address: u32) -> Result<u32, Error> {
        self.0.admit()?;
        let value = self.0.read32(address)?;
        if value == u32::MAX {
            Err(power::Error::Gone.into())
        } else {
            Ok(value)
        }
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
    fn program(&mut self, ops: &[Op]) -> Result<(), Error> {
        for &op in ops {
            match op {
                Op::Write(address, value) => self.write(address, value)?,
                Op::Field(address, mask, value) => self.field(address, mask, value)?,
            }
        }
        Ok(())
    }
    async fn xtal_read(&mut self, address: u8) -> Result<u8, Error> {
        self.0.admit()?;
        let value = self.0.xtal_read(address).await?;
        self.0.admit()?;
        Ok(value)
    }
    async fn xtal_write(&mut self, address: u8, value: u8) -> Result<(), Error> {
        self.0.admit()?;
        self.0.xtal_write(address, value, 255).await?;
        self.0.admit()
    }
    fn physts(&mut self) -> Result<(), Error> {
        self.field(0x20738, 8, 1)?;
        self.field(0x20738, 4, 1)?;
        for page in 0..17 {
            if page == 9 {
                continue;
            }
            let address = if page == 16 {
                0x20788
            } else {
                0x2073c + page * 4
            };
            let old = self.read(address)?;
            let value = if page == 6 || page == 7 {
                old | 0x2000
            } else if page == 10 {
                old | 0x2002
            } else if page >= 11 {
                (old & !0xf0)
                    | if page == 11 {
                        2
                    } else if page >= 13 {
                        0x100000
                    } else {
                        0
                    }
            } else {
                old
            };
            self.write(address, value)?;
        }
        Ok(())
    }
}
/// Source bb_postinit after BB/gain tables and before RF table programming.
/// Only PHY0 runs in SCC. Native common packet/MAC1 closure remains required
/// at every effect, including the two common FEN writes.
pub(super) fn post_bb(io: &mut impl Interface) -> Result<(), Error> {
    Access(io).program(program::BB_POST)
}
impl Operating {
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn fixture_packet_refusal_metadata() -> Self {
        Self {
            state: State::CompleteMac1Restored,
            ..Self::default()
        }
    }
    pub(super) fn state(&self) -> State {
        self.state
    }
    pub(super) fn partial(&self) -> Option<Working> {
        (self.state == State::PartialMac1Off)
            .then_some(self.working)
            .flatten()
    }
    /// Issue source cold SCC channel1/20MHz DM fields and actual CFO/PLL
    /// analog accesses, preserving the explicit unused-MAC1 omission. The
    /// subsequent correct BE NCTL table, software RFK reset, power trim and
    /// Tx/Rx path/reset bracket remain separate ordered composition stages.
    ///
    /// # Safety
    /// Actual original RTL8922A after its complete selected BB/RF table
    /// programs, on current qualified channel1/20MHz with CMAC0 packets
    /// positively closed and MAC1 fully off/isolated. Interface wraps EVERY
    /// actual MMIO/XTAL/RF effect in current device and signed qualification
    /// authority for this exact partial source program. No legacy N22A-v1
    /// record, guessed factory/thermal input or ordinary packet grant suffices.
    /// Error/cancellation terminalizes the enclosing owner and retains DMA.
    pub(super) async unsafe fn prepare_scc_partial(
        &mut self,
        io: &mut impl Interface,
        factory: &BeFactory,
        identity: HalChipVer,
    ) -> Result<(), Error> {
        // SAFETY: caller supplies the documented original closed SCC owner,
        // actual factory/CV and per-effect current partial source scope.
        // false preserves the partial program's explicit MAC1 omission.
        unsafe { self.prepare_scc(io, factory, identity, false).await }
    }
    /// # Safety
    /// Same original closed radio as prepare_scc_partial, with a distinct
    /// fresh N22W contract and retained checked MAC1 power-window owner.
    pub(super) async unsafe fn prepare_scc_complete(
        &mut self,
        io: &mut impl Interface,
        factory: &BeFactory,
        identity: HalChipVer,
    ) -> Result<(), Error> {
        // SAFETY: caller supplies the same original closed SCC inputs plus
        // the distinct current N22W contract and retained MAC1 window. true
        // routes MAC1 UL effects through that checked window, never a raw
        // off-domain access; error/drop retains the one-shot Busy owner.
        unsafe { self.prepare_scc(io, factory, identity, true).await }
    }
    async unsafe fn prepare_scc(
        &mut self,
        io: &mut impl Interface,
        factory: &BeFactory,
        identity: HalChipVer,
        complete: bool,
    ) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        self.state = State::Busy;
        if identity.cv > 14
            || factory.cv.is_some_and(|cv| cv != identity.cv)
            || factory.rfe_type == 255
            || !super::efuse::mac_is_valid(factory.mac)
        {
            return Err(Error::Policy);
        }
        io.admit()?;
        let mut thermal = [Thermal::DisabledByProfile; 2];
        for (path, sample) in thermal.iter_mut().enumerate() {
            io.admit()?;
            *sample = io.thermal(path as u8).await?;
            io.admit()?;
        }
        let mut a = Access(io);
        a.program(program::SET_HW20)?;
        a.program(program::ENV)?;
        // support_noise=false, so no NHM effects are invented.
        a.physts()?;
        a.program(program::DIG20)?;
        let crystal = factory.xtal_cap & 0x7f;
        a.xtal_write(5, crystal).await?;
        a.xtal_write(4, crystal).await?;
        let xo = a.xtal_read(5).await?;
        let xi = a.xtal_read(4).await?;
        if xo != crystal || xi != crystal {
            return Err(Error::Terminal);
        }
        a.program(program::DCFO)?;
        a.program(program::BB_WRAP_SCC_NATIVE)?;
        if complete {
            a.0.mac1_ul_power()?;
        }
        if identity.cv == 0 {
            a.program(program::EDCCA_CAV)?;
        }
        a.program(program::EDCCA)?;
        a.program(program::CH_INFO)?;
        // ul_tb_waveform_ctrl=false, no antenna-diversity owner and
        // rfe_gpio=NULL. Non-DBCC RFK HW init only runs these PLL steps.
        let pll = a.xtal_read(0xe1).await?;
        a.xtal_write(0xe1, pll | 0xf8).await?;
        let apbt = a.xtal_read(0xd1).await?;
        a.xtal_write(0xd1, apbt & !0x60).await?;
        let xtal = a.xtal_read(0x16).await?;
        a.xtal_write(0x16, xtal | 0x38).await?;
        a.0.admit()?;
        self.working = Some(Working {
            crystal_default: crystal,
            crystal_actual: xi,
            crystal_lower: crystal.saturating_sub(64).max(1),
            crystal_upper: crystal.saturating_add(64).min(127),
            thermal,
        });
        self.state = if complete {
            State::CompleteMac1Restored
        } else {
            State::PartialMac1Off
        };
        Ok(())
    }
}
