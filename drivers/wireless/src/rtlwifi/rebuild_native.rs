// SPDX-License-Identifier: GPL-2.0-or-later
//! Fresh firmware and packet rings after verified physical retirement.
use super::*;
impl
    recovery::Rebuild<
        super::super::firmware_transport::PacketIo<super::super::firmware_native::PciIo>,
        super::super::prepare_native::Coherent,
    > for NativeEnvironment
{
    async fn power_down(&self) -> Result<(), Error> {
        use super::super::{firmware_transport::Stage, prepare};
        match self.power_state.load(Ordering::Acquire) {
            1 => return Ok(()),
            0 => {}
            _ => return Err(Error::State),
        }
        let firmware = self.firmware();
        let io = firmware
            .native()
            .parked_control()
            .map_err(prepare::Error::Access)?;
        io.disable_aspm().map_err(prepare::Error::Access)?;
        self.power_state.store(2, Ordering::Release);
        let ready = firmware.status().stage == Stage::Ready;
        let rtl8821ae = firmware.device_id() == super::super::regs::RTL_DEV_8821AE;
        let disabled = if rtl8821ae {
            super::super::power_runtime::disable_rtl8821ae(&io, ready).await
        } else {
            super::super::power_runtime::disable(&io, ready).await
        };
        disabled.map_err(prepare::Error::Access)?;
        self.power_state.store(1, Ordering::Release);
        if rtl8821ae {
            // ASPM is not composed for 8821AE (`prepare_bus_power`): the
            // probe's ASPM-disabled link state is kept.
            return Ok(());
        }
        // Card-disable proof is complete. Optional idle-link optimization
        // cannot revoke that receipt or grant any packet/DMA ownership.
        let _ = firmware
            .native()
            .idle_aspm(PCIE_ASPM.load(Ordering::Acquire))
            .await;
        Ok(())
    }
    async fn rebuild(
        &self,
        retained: Arc<super::super::prepare_native::Retained>,
        factory: Arc<Factory>,
        channel: u8,
    ) -> Result<(), Error> {
        use super::super::{
            firmware_transport::Owner,
            prepare,
            regs::{RTL_DEV_8188EE, RTL_DEV_8821AE},
        };
        // The fresh-generation rebuild is the card-disable/enable flow:
        // 88EE `_rtl88ee_poweroff_adapter` + NIC enable, 8821AE
        // `_rtl8821ae_poweroff_adapter` + `_rtl8821ae_init_mac`'s enable.
        let device = self.firmware().device_id();
        if !matches!(device, RTL_DEV_8188EE | RTL_DEV_8821AE) {
            return Err(Error::State);
        }
        self.power_down().await?;
        let old = self.firmware();
        let io = old
            .native()
            .parked_control()
            .map_err(prepare::Error::Access)?;
        io.disable_aspm().map_err(prepare::Error::Access)?;
        self.power_state.store(2, Ordering::Release);
        let enabled = if device == RTL_DEV_8821AE {
            super::super::power_runtime::enable_rtl8821ae(&io).await
        } else {
            super::super::power_runtime::enable(&io).await
        };
        enabled.map_err(prepare::Error::Access)?;
        self.power_state.store(0, Ordering::Release);
        io.verify_factory(&factory)
            .map_err(prepare::Error::Access)?;
        let firmware = Arc::new(Owner::new(io, device));
        *self.firmware.lock() = firmware.clone();
        super::super::prepare_native::initialize_registered_on_channel(
            firmware.clone(),
            retained,
            factory,
            channel,
        )
        .await?;
        firmware.native().arm_msi();
        Ok(())
    }
}
impl Native {
    pub(in crate::rtlwifi) fn native_firmware(
        &self,
    ) -> Arc<super::super::firmware_transport::Owner<super::super::firmware_native::PciIo>> {
        self.environment.firmware()
    }
    pub(in crate::rtlwifi) async fn provision(&self) -> Result<(), super::super::prepare::Error> {
        let _control = self.lifecycle.control.lock().await;
        if self.removed.load(Ordering::Acquire)
            || self.lifecycle.rebuilding.load(Ordering::Acquire)
            || self.lifecycle.suspended.load(Ordering::Acquire)
            || self.admission.closed.load(Ordering::Acquire)
        {
            return Err(super::super::prepare::Error::State);
        }
        super::super::prepare_native::initialize_registered_on_channel(
            self.environment.firmware(),
            self.prepared.clone(),
            self.factory.clone(),
            self.lifecycle.channel.load(Ordering::Acquire),
        )
        .await
    }
}
