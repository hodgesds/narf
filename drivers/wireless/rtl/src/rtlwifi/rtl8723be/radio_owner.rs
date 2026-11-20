// SPDX-License-Identifier: GPL-2.0-or-later
//! Radio steps of the retained RTL8723BE owner (`rtl8723be/init.rs`),
//! mounted under `prepare`. Packet DMA, CR gates and IRQs stay closed.

use super::{Chip, Error, Memory, Phase, Prepared};
use crate::rtlwifi::btcoex::btc::HwPg;
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::rtl8723be::{adapter, channel, coex, envelope, init, txpower, version};

impl<I: Io, M: Memory> Prepared<I, M> {
    /// Allocated → Allocated: `rtl_btc_init_variables` for the board facts
    /// probe read (`rtl8723be_read_bt_coexist_info_from_hwpg`).
    /// [`Self::configure_rtl8723be`] refuses a live re-read that differs.
    pub fn bind_rtl8723be_coex(&mut self, pg: HwPg) -> Result<(), Error> {
        if self.phase != Phase::Allocated
            || self.chip != Chip::Rtl8723be
            || self.rtl8723be_coex.is_some()
        {
            return Err(Error::State);
        }
        self.rtl8723be_coex = Some(alloc::boxed::Box::new(coex::Owner::bind(pg)));
        Ok(())
    }

    /// Allocated → Allocated: [`Self::bind_rtl8723be_coex`] with the
    /// `rtl8723be_read_bt_coexist_info_from_hwpg` facts measured over this
    /// owner's registers (the [`Self::configure_rtl8723be`] reads:
    /// `_rtl8723be_read_chip_version`, `REG_9346CR`, `REG_MULTI_FUNC_CTRL`,
    /// the retained logical map and the measured physical `0x1fb` byte).
    pub fn bind_rtl8723be_coex_measured(
        &mut self,
        factory: &crate::rtlwifi::efuse::Factory,
        efuse_0x1fb: u8,
    ) -> Result<(), Error> {
        if self.phase != Phase::Allocated || self.chip != Chip::Rtl8723be {
            return Err(Error::State);
        }
        let facts = self.rtl8723be_facts(factory, efuse_0x1fb)?;
        self.bind_rtl8723be_coex(HwPg::rtl8723be(&facts))
    }

    fn rtl8723be_facts(
        &self,
        factory: &crate::rtlwifi::efuse::Factory,
        efuse_0x1fb: u8,
    ) -> Result<adapter::Adapter, Error> {
        let sys_cfg1 = self.io.read32(version::REG_SYS_CFG1)?;
        let sys_cfg = self.io.read32(version::REG_SYS_CFG)?;
        let multi_func_ctrl = self.io.read32(adapter::REG_MULTI_FUNC_CTRL)?;
        if sys_cfg1 == u32::MAX || sys_cfg == u32::MAX || multi_func_ctrl == u32::MAX {
            return Err(Error::Access(
                crate::rtlwifi::firmware_transport::Error::Gone,
            ));
        }
        let qualified =
            version::Version::from_registers(sys_cfg1, sys_cfg).map_err(|_| Error::State)?;
        adapter::Adapter::from_hardware(
            qualified,
            self.io.read8(adapter::REG_9346CR)?,
            multi_func_ctrl,
            &factory.logical,
            efuse_0x1fb,
        )
        .map_err(|_| Error::State)
    }

    /// The coexistence owner (the station/packet owner drives its notify
    /// call sites and C2H delivery through it).
    pub fn rtl8723be_coex(&mut self) -> Option<&mut coex::Owner> {
        self.rtl8723be_coex.as_deref_mut()
    }

    /// `rtl_pci_stop` (`pci.c:1774`): `btc_halt_notify` before interrupts
    /// and the adapter are disabled. Idempotent once unbound.
    pub async fn halt_rtl8723be_coex(&mut self) -> Result<(), Error> {
        if self.chip != Chip::Rtl8723be {
            return Err(Error::State);
        }
        let Some(coex) = self.rtl8723be_coex.as_deref_mut() else {
            return Ok(());
        };
        coex.halt(&self.io).await
    }

    /// The configured RTL8723BE radio facts, if any.
    pub fn rtl8723be_radio(&self) -> Option<&init::Radio> {
        self.rtl8723be.as_deref().map(|(_, radio)| radio)
    }

    /// Prepared → RadioConfigured: the `rtl8723be_hw_init` steps after the
    /// firmware download over the retained factory map. The version is
    /// re-qualified from live `REG_SYS_CFG1` / `REG_SYS_CFG` and the adapter
    /// facts from live `REG_9346CR` / `REG_MULTI_FUNC_CTRL`; `efuse_0x1fb`
    /// is the physical package byte probe measured
    /// (`_rtl8723be_read_package_type`, 0 after a read timeout). An
    /// unprovisioned map, a MAC differing from the factory identity or a map
    /// without path-A TX power ([`txpower::Efuse::from_logical`]) is refused
    /// before the first table write.
    pub async fn configure_rtl8723be(
        &mut self,
        factory: &crate::rtlwifi::efuse::Factory,
        efuse_0x1fb: u8,
    ) -> Result<(), Error> {
        if self.phase != Phase::Prepared || self.chip != Chip::Rtl8723be {
            return Err(Error::State);
        }
        let facts = self.rtl8723be_facts(factory, efuse_0x1fb)?;
        if facts.mac != factory.mac {
            return Err(Error::State);
        }
        let efuse = txpower::Efuse::from_logical(&factory.logical)?;
        let coex = self.rtl8723be_coex.as_deref_mut().ok_or(Error::State)?;
        let mut bound = coex::Owner::bind(HwPg::rtl8723be(&facts)).btc.board_info;
        // `btdm_ant_pos` is the power-on handler's to move.
        bound.btdm_ant_pos = coex.btc.board_info.btdm_ant_pos;
        if bound != coex.btc.board_info || coex.btc.bt_exist != facts.bt_coexist {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        let radio = init::configure(&self.io, &facts, efuse, coex).await?;
        let identity = crate::rtlwifi::radio::factory_identity(factory);
        self.rtl8723be = Some(alloc::boxed::Box::new((identity, radio)));
        self.phase = Phase::RadioConfigured;
        Ok(())
    }

    /// The admitted `NAPC` operating point the channel was programmed at.
    pub fn rtl8723be_permission(&self) -> Option<envelope::Permission> {
        self.rtl8723be_power
    }

    /// RadioConfigured/ChannelConfigured/MacConfigured/Running → the same
    /// phase (ChannelConfigured from RadioConfigured): the `rtl_op_config`
    /// channel change at `op` with the [`channel::Grant`] the signed `NAPC`
    /// envelope mints for this board ([`envelope::Calibration::grant_for`]:
    /// every TXAGC index measured, admitted under current host policy and
    /// capped at the Linux `rtl8723be_phy_set_txpower_level` index for the
    /// configured EFUSE power, PHY_REG_PG by-rate store and regulatory
    /// option). The envelope must have been minted for this owner's
    /// factory identity. A station retune (MacConfigured/Running) keeps the
    /// packet phase; packet DMA, CR gates and IRQs are not touched; any I/O
    /// failure fails the owner.
    pub async fn configure_rtl8723be_channel(
        &mut self,
        calibration: &envelope::Calibration,
        domain: &narf_wireless::reg::RegulatoryDomain,
        op: envelope::Operating,
    ) -> Result<(), Error> {
        let resume = match self.phase {
            Phase::RadioConfigured | Phase::ChannelConfigured => Phase::ChannelConfigured,
            Phase::MacConfigured | Phase::Running => self.phase,
            _ => return Err(Error::State),
        };
        if self.chip != Chip::Rtl8723be {
            return Err(Error::State);
        }
        let Some((identity, radio)) = self.rtl8723be.as_deref() else {
            return Err(Error::State);
        };
        let permission = calibration
            .permission_for(domain, op)
            .map_err(Error::Power)?;
        let grant = calibration
            .grant_for(
                domain,
                &radio.efuse,
                &radio.by_rate,
                radio.adapter.regulatory,
                op,
            )
            .map_err(Error::Power)?;
        if *identity != grant.identity() || *identity != permission.identity() {
            return Err(Error::Power(crate::rtlwifi::channel_power::Error::Identity));
        }
        let mut state = self.rtl8723be.take().ok_or(Error::State)?;
        self.phase = Phase::Failed;
        self.rtl8723be_power = None;
        channel::configure(&self.io, &grant, &mut state.1.chnlval).await?;
        self.rtl8723be = Some(state);
        self.rtl8723be_power = Some(permission);
        self.phase = resume;
        Ok(())
    }

    /// ChannelConfigured → MacConfigured: the station address
    /// (`configure_rtl8723be` wrote `HW_VAR_ETHER_ADDR`) for the factory
    /// identity the channel permission was minted for. Packet DMA, CR gates
    /// and IRQs stay closed.
    pub fn configure_rtl8723be_mac(
        &mut self,
        factory: &crate::rtlwifi::efuse::Factory,
    ) -> Result<(), Error> {
        if self.phase != Phase::ChannelConfigured || self.chip != Chip::Rtl8723be {
            return Err(Error::State);
        }
        let identity = crate::rtlwifi::radio::factory_identity(factory);
        if self.rtl8723be.as_ref().map(|state| state.0) != Some(identity)
            || self.rtl8723be_power.map(|p| p.identity()) != Some(identity)
        {
            return Err(Error::Power(crate::rtlwifi::channel_power::Error::Identity));
        }
        self.packet.local = Some(factory.mac);
        self.phase = Phase::MacConfigured;
        Ok(())
    }
}
