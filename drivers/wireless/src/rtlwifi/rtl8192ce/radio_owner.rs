// SPDX-License-Identifier: GPL-2.0-or-later
//! Radio/channel steps of the retained RTL8192CE / RTL8188CE owner
//! (`rtl8192ce/init.rs`, `rtl8192ce/channel.rs`), mounted under `prepare`.
//! Packet DMA, CR gates and IRQs stay closed.

use super::{Chip, Error, Memory, Phase, Prepared};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::rtl8192ce::{adapter, channel, envelope, init, txpower, version};

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
    /// factory identity are refused before the first table write. `device`
    /// is the probed `rtl92ce_pci_ids` function the `N92C` envelope binds.
    pub async fn configure_rtl8192ce(
        &mut self,
        factory: &crate::rtlwifi::efuse::Factory,
        device: u16,
    ) -> Result<(), Error> {
        if self.phase != Phase::Prepared
            || self.chip != Chip::Rtl8192ce
            || !crate::rtlwifi::rtl8192ce::is_8192ce(device)
        {
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
        self.packet.ce92.device = Some(device);
        self.phase = Phase::RadioConfigured;
        Ok(())
    }

    /// The probed PCI device and measured RF type of the configured radio
    /// (the `N92C` envelope's binding), if any.
    pub(crate) fn rtl8192ce_binding(&self) -> Option<(u16, version::RfType)> {
        Some((
            self.packet.ce92.device?,
            self.rtl8192ce_radio()?.version.rf_type(),
        ))
    }

    /// Admitted CE operating point committed by
    /// [`Self::configure_rtl8192ce_channel`].
    pub fn rtl8192ce_permission(&self) -> Option<envelope::Permission> {
        self.rtl8192ce_power
    }

    /// `mac->cur_40_prime_sc` of the programmed `N92C` operating point (0
    /// at 20 MHz or without a permission).
    pub(crate) fn rtl8192ce_prime_sc(&self) -> u8 {
        self.rtl8192ce_power
            .and_then(|p| envelope::channel_of(p.operating()))
            .map_or(0, |c| c.prime_sc)
    }

    /// RadioConfigured/ChannelConfigured/MacConfigured/Running → the same
    /// phase (ChannelConfigured from RadioConfigured): `rtl_op_config`
    /// channel switch at the wide channel with the envelope-admitted
    /// per-path TXAGC indices, then the 20/40 MHz bandwidth
    /// (`rtl8192ce/channel.rs::configure_admitted`). The permission must
    /// have been minted for this owner's factory identity and measured RF
    /// type. A station retune (MacConfigured/Running) keeps the packet
    /// phase; any I/O failure fails the owner.
    pub async fn configure_rtl8192ce_channel(
        &mut self,
        permission: envelope::Permission,
    ) -> Result<(), Error> {
        let resume = match self.phase {
            Phase::RadioConfigured | Phase::ChannelConfigured => Phase::ChannelConfigured,
            Phase::MacConfigured | Phase::Running => self.phase,
            _ => return Err(Error::State),
        };
        if self.chip != Chip::Rtl8192ce {
            return Err(Error::State);
        }
        let Some(state) = self.rtl8192ce.as_ref() else {
            return Err(Error::State);
        };
        if state.0 != permission.identity() {
            return Err(Error::Power(crate::rtlwifi::channel_power::Error::Identity));
        }
        if state.1.version.rf_type() != permission.rf_type() {
            return Err(Error::State);
        }
        let mut state = self.rtl8192ce.take().ok_or(Error::State)?;
        self.phase = Phase::Failed;
        self.rtl8192ce_power = None;
        let version = state.1.version;
        channel::configure_admitted(&self.io, version, &permission, &mut state.1.chnlval).await?;
        self.rtl8192ce = Some(state);
        self.rtl8192ce_power = Some(permission);
        self.packet.ce92.channel = Some(permission.channel());
        self.phase = resume;
        Ok(())
    }

    /// ChannelConfigured → MacConfigured: the station address
    /// (`configure_rtl8192ce` wrote `HW_VAR_ETHER_ADDR`) for the factory
    /// identity the channel permission was minted for. BT-coexist boards
    /// were refused by [`Self::configure_rtl8192ce`]. Packet DMA, CR gates
    /// and IRQs stay closed.
    pub fn configure_rtl8192ce_mac(
        &mut self,
        factory: &crate::rtlwifi::efuse::Factory,
    ) -> Result<(), Error> {
        if self.phase != Phase::ChannelConfigured || self.chip != Chip::Rtl8192ce {
            return Err(Error::State);
        }
        let identity = crate::rtlwifi::radio::factory_identity(factory);
        if self.rtl8192ce.as_ref().map(|state| state.0) != Some(identity)
            || self.rtl8192ce_power.map(|p| p.identity()) != Some(identity)
        {
            return Err(Error::Power(crate::rtlwifi::channel_power::Error::Identity));
        }
        self.packet.local = Some(factory.mac);
        self.phase = Phase::MacConfigured;
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
