// SPDX-License-Identifier: GPL-2.0-or-later
//! Radio steps of the retained RTL8723BE owner (`rtl8723be/init.rs`),
//! mounted under `prepare`. Packet DMA, CR gates and IRQs stay closed.

use super::{Chip, Error, Memory, Phase, Prepared};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::rtl8723be::{adapter, init, version};

impl<I: Io, M: Memory> Prepared<I, M> {
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
    /// unprovisioned map or a MAC differing from the factory identity is
    /// refused before the first table write.
    pub async fn configure_rtl8723be(
        &mut self,
        factory: &crate::rtlwifi::efuse::Factory,
        efuse_0x1fb: u8,
    ) -> Result<(), Error> {
        if self.phase != Phase::Prepared || self.chip != Chip::Rtl8723be {
            return Err(Error::State);
        }
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
        let facts = adapter::Adapter::from_hardware(
            qualified,
            self.io.read8(adapter::REG_9346CR)?,
            multi_func_ctrl,
            &factory.logical,
            efuse_0x1fb,
        )
        .map_err(|_| Error::State)?;
        if facts.mac != factory.mac {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        let radio = init::configure(&self.io, &facts).await?;
        let identity = crate::rtlwifi::radio::factory_identity(factory);
        self.rtl8723be = Some(alloc::boxed::Box::new((identity, radio)));
        self.phase = Phase::RadioConfigured;
        Ok(())
    }
}
