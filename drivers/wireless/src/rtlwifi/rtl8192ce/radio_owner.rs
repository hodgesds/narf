// SPDX-License-Identifier: GPL-2.0-or-later
//! Radio/channel steps of the retained RTL8192CE / RTL8188CE owner
//! (`rtl8192ce/init.rs`, `rtl8192ce/channel.rs`), mounted under `prepare`.
//! Packet DMA, CR gates and IRQs stay closed.

use super::{Chip, Error, Memory, Phase, Prepared};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::rtl8192ce::{adapter, channel, init, txpower, version};

impl<I: Io, M: Memory> Prepared<I, M> {
    /// The configured RTL8192CE / RTL8188CE radio facts, if any.
    pub fn rtl8192ce_radio(&self) -> Option<&init::Radio> {
        self.rtl8192ce.as_deref().map(|(_, radio)| radio)
    }

    /// Prepared → RadioConfigured: the `rtl92ce_hw_init` steps after the
    /// firmware download over the retained factory map. The version is
    /// re-qualified from live `REG_SYS_CFG` / `REG_HPON_FSM` and the adapter
    /// facts from `REG_9346CR`; test chips, 1T2R bondings, unknown cuts,
    /// unprovisioned maps, BT-coexist boards and a MAC differing from the
    /// factory identity are refused before the first table write.
    pub async fn configure_rtl8192ce(
        &mut self,
        factory: &crate::rtlwifi::efuse::Factory,
    ) -> Result<(), Error> {
        if self.phase != Phase::Prepared || self.chip != Chip::Rtl8192ce {
            return Err(Error::State);
        }
        let qualified = radio_version(&self.io)?;
        let facts = adapter::Adapter::from_hardware(
            qualified,
            self.io.read8(adapter::REG_9346CR)?,
            &factory.logical,
        )
        .map_err(|_| Error::State)?;
        if facts.bt_coexistence() || facts.mac != factory.mac {
            return Err(Error::State);
        }
        txpower::Efuse::from_hwinfo(&facts.hwinfo)?;
        self.phase = Phase::Failed;
        let radio = init::configure(&self.io, &facts).await?;
        let identity = crate::rtlwifi::radio::factory_identity(factory);
        self.rtl8192ce = Some(alloc::boxed::Box::new((identity, radio)));
        self.phase = Phase::RadioConfigured;
        Ok(())
    }

    /// RadioConfigured/ChannelConfigured → ChannelConfigured: `rtl_op_config`
    /// channel switch and 20/40 MHz bandwidth with the factory TX power.
    pub async fn configure_rtl8192ce_channel(
        &mut self,
        op: channel::Operating,
    ) -> Result<(), Error> {
        if !matches!(
            self.phase,
            Phase::RadioConfigured | Phase::ChannelConfigured
        ) || self.chip != Chip::Rtl8192ce
        {
            return Err(Error::State);
        }
        let mut state = self.rtl8192ce.take().ok_or(Error::State)?;
        self.phase = Phase::Failed;
        let radio = &mut state.1;
        let (version, power, groups) = (radio.version, radio.power, radio.phy.pg.pwrgroup_cnt);
        channel::configure(&self.io, version, &power, groups, &op, &mut radio.chnlval).await?;
        self.rtl8192ce = Some(state);
        self.packet.ce92.channel = Some(op.primary);
        self.phase = Phase::ChannelConfigured;
        Ok(())
    }
}

/// `_rtl92ce_read_chip_version` over live registers (HPON_FSM only for
/// 92C-serial parts); any unqualified version is refused.
fn radio_version(io: &impl Io) -> Result<version::Version, Error> {
    let sys_cfg = io.read32(version::REG_SYS_CFG)?;
    let mut hpon = Ok(0);
    let v = version::Version::from_registers(sys_cfg, || {
        hpon = io.read32(version::REG_HPON_FSM);
        *hpon.as_ref().unwrap_or(&0)
    });
    hpon?;
    v.map_err(|_| Error::State)
}
