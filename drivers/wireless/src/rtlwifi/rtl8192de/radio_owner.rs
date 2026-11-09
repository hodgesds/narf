// SPDX-License-Identifier: GPL-2.0-or-later
//! Radio/channel steps of the retained RTL8192DE owner
//! (`rtl8192de/init.rs`, `rtl8192de/channel.rs`, `rtl8192de/version.rs`),
//! mounted under `prepare`. Packet DMA, CR gates and IRQs stay closed.

use super::{Chip, Error, Memory, Phase, Prepared};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::regs::RTL_DEV_8192DE;
use crate::rtlwifi::rtl8192de::{
    channel, envelope, init, mode_from_prom, mode_info, sw_consequences, txpower, version, BandSet,
    Interface, MacPhyMode, RfType,
};

/// RTL8192DE factory identity, configured radio, factory TX-power data
/// and the channel bandset the channel step owns and records.
#[derive(Clone, Copy, Debug)]
pub struct De92Radio {
    /// Factory identity the `N92D` envelope binds.
    pub identity: [u8; 32],
    /// The `rtl92de_hw_init` report.
    pub radio: init::Radio,
    /// Factory TX-power data (from the EFUSE logical map).
    pub efuse: txpower::Efuse,
    /// Channel bandset (`switch_wirelessband` records the switch).
    pub bandset: BandSet,
}

impl<I: Io, M: Memory> Prepared<I, M> {
    /// The configured RTL8192DE radio facts, if any.
    pub fn rtl8192de_radio(&self) -> Option<&init::Radio> {
        self.rtl8192de.as_deref().map(|state| &state.radio)
    }

    /// Allocated → Allocated: bind the MAC/PHY mode the PROM read
    /// derives, so [`Self::prepare`] can run the mode-dependent LLT
    /// before the radio is configured. [`Self::configure_rtl8192de`]
    /// refuses a live re-read that differs.
    pub fn bind_rtl8192de_mode(&mut self, mode: MacPhyMode) -> Result<(), Error> {
        if self.phase != Phase::Allocated
            || self.chip != Chip::Rtl8192de
            || self.rtl8192de_mode.is_some()
        {
            return Err(Error::State);
        }
        self.rtl8192de_mode = Some(mode);
        Ok(())
    }

    /// Prepared → RadioConfigured: the `rtl92de_hw_init` tail after the
    /// firmware download over the retained factory map. The mode is
    /// re-derived from the PROM and must equal the bound mode; test chips
    /// are refused; the autoload flag comes from live `REG_9346CR` and
    /// the D/E cut from the EFUSE chip-version word, so the TX-power
    /// data is built from qualified facts before the first table write.
    /// `interface_index` is the probed PCI function (0 = MAC0, 1 = MAC1).
    pub async fn configure_rtl8192de(
        &mut self,
        factory: &crate::rtlwifi::efuse::Factory,
        interface_index: u8,
    ) -> Result<(), Error> {
        if self.phase != Phase::Prepared || self.chip != Chip::Rtl8192de || interface_index > 1 {
            return Err(Error::State);
        }
        let mode = self.rtl8192de_mode.ok_or(Error::State)?;
        if mode_from_prom(Interface::Pci, &factory.logical) != Some(mode) {
            return Err(Error::State);
        }
        if version::is_test_chip(&self.io)? {
            return Err(Error::State);
        }
        let autoload_fail = version::autoload_failed(&self.io)?;
        let cut = version::read_cut(&self.io).await?;
        let efuse =
            txpower::Efuse::from_hwinfo(&factory.logical[..256], autoload_fail, cut.d_or_e_cut())?;
        let info = mode_info(mode, interface_index);
        let default_channel = sw_consequences(mode, info.current_band).default_channel;
        self.phase = Phase::Failed;
        let radio = init::configure(
            &self.io,
            &init::Params {
                mode,
                interface_index,
                band: info.current_band,
                mac: factory.mac,
                efuse,
                rf_type: info.rf_type,
                channel: default_channel,
                bw40: false,
                autoload_fail,
            },
        )
        .await?;
        let identity = crate::rtlwifi::radio::factory_identity(factory);
        self.rtl8192de = Some(alloc::boxed::Box::new(De92Radio {
            identity,
            radio,
            efuse,
            bandset: info.bandset,
        }));
        self.phase = Phase::RadioConfigured;
        Ok(())
    }

    /// The probed PCI device and measured RF type of the configured radio
    /// (the `N92D` envelope's binding), if any.
    pub(crate) fn rtl8192de_binding(&self) -> Option<(u16, RfType)> {
        Some((RTL_DEV_8192DE, self.rtl8192de_radio()?.rf_type))
    }

    /// Admitted DE operating point committed by
    /// [`Self::configure_rtl8192de_channel`].
    pub fn rtl8192de_permission(&self) -> Option<envelope::Permission> {
        self.rtl8192de_power
    }

    /// RadioConfigured/ChannelConfigured → the same phase
    /// (ChannelConfigured from RadioConfigured): `rtl_op_config` channel
    /// switch at the wide channel with the envelope-admitted TX power,
    /// then the 20/40 MHz bandwidth (`rtl8192de/channel.rs::configure`).
    /// The permission must have been minted for this owner's factory
    /// identity. A station retune (MacConfigured/Running) keeps the
    /// packet phase; any I/O failure fails the owner. An
    /// autoload-failed board has no power-group store, so its channel
    /// step is refused: there is no TX-power data to tune with.
    pub async fn configure_rtl8192de_channel(
        &mut self,
        permission: envelope::Permission,
    ) -> Result<(), Error> {
        let resume = match self.phase {
            Phase::RadioConfigured | Phase::ChannelConfigured => Phase::ChannelConfigured,
            Phase::MacConfigured | Phase::Running => self.phase,
            _ => return Err(Error::State),
        };
        if self.chip != Chip::Rtl8192de {
            return Err(Error::State);
        }
        let Some(state) = self.rtl8192de.as_ref() else {
            return Err(Error::State);
        };
        if state.identity != permission.identity() {
            return Err(Error::Power(crate::rtlwifi::channel_power::Error::Identity));
        }
        if state.radio.pg.is_none() {
            return Err(Error::State);
        }
        let operating = permission.operating();
        let kind = match operating.width {
            envelope::Width::W20 => channel::ChannelType::Ht20,
            envelope::Width::W40Above => channel::ChannelType::Ht40Plus,
            envelope::Width::W40Below => channel::ChannelType::Ht40Minus,
        };
        let op = channel::Operating::new(operating.channel, kind)?;
        let mut state = self.rtl8192de.take().ok_or(Error::State)?;
        self.phase = Phase::Failed;
        self.rtl8192de_power = None;
        let single_phy = state.radio.rf_type == RfType::TwoT2R;
        let pg = state.radio.pg.as_ref().ok_or(Error::State)?;
        let outcome = channel::configure(
            &self.io,
            &state.efuse,
            pg,
            state.radio.rf_type,
            state.radio.mode,
            state.radio.interface_index,
            &mut state.radio.band,
            &mut state.bandset,
            single_phy,
            &op,
            &mut state.radio.chnlval,
        )
        .await?;
        state.bandset = outcome.bandset;
        self.rtl8192de = Some(state);
        self.rtl8192de_power = Some(permission);
        self.phase = resume;
        Ok(())
    }

    /// ChannelConfigured → MacConfigured: the station address
    /// (`configure_rtl8192de` wrote `HW_VAR_ETHER_ADDR`) for the factory
    /// identity the channel permission was minted for. Packet DMA, CR
    /// gates and IRQs stay closed.
    pub fn configure_rtl8192de_mac(
        &mut self,
        factory: &crate::rtlwifi::efuse::Factory,
    ) -> Result<(), Error> {
        if self.phase != Phase::ChannelConfigured || self.chip != Chip::Rtl8192de {
            return Err(Error::State);
        }
        let identity = crate::rtlwifi::radio::factory_identity(factory);
        if self.rtl8192de.as_ref().map(|state| state.identity) != Some(identity)
            || self.rtl8192de_power.map(|p| p.identity()) != Some(identity)
        {
            return Err(Error::Power(crate::rtlwifi::channel_power::Error::Identity));
        }
        self.packet.local = Some(factory.mac);
        self.phase = Phase::MacConfigured;
        Ok(())
    }
}
