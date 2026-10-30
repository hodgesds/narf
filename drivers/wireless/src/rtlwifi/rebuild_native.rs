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
        self.power_state.store(2, Ordering::Release);
        super::super::power_runtime::disable(&io, firmware.status().stage == Stage::Ready)
            .await
            .map_err(prepare::Error::Access)?;
        self.power_state.store(1, Ordering::Release);
        Ok(())
    }
    async fn rebuild(
        &self,
        retained: Arc<super::super::prepare_native::Retained>,
        factory: Arc<Factory>,
    ) -> Result<(), Error> {
        use super::super::{firmware_transport::Owner, prepare, regs::RTL_DEV_8188EE};
        self.power_down().await?;
        let old = self.firmware();
        let io = old
            .native()
            .parked_control()
            .map_err(prepare::Error::Access)?;
        self.power_state.store(2, Ordering::Release);
        super::super::power_runtime::enable(&io)
            .await
            .map_err(prepare::Error::Access)?;
        self.power_state.store(0, Ordering::Release);
        io.verify_factory(&factory)
            .map_err(prepare::Error::Access)?;
        let firmware = Arc::new(Owner::new(io, RTL_DEV_8188EE));
        *self.firmware.lock() = firmware.clone();
        super::super::prepare_native::initialize_registered(firmware.clone(), retained, factory)
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
        super::super::prepare_native::initialize_registered(
            self.environment.firmware(),
            self.prepared.clone(),
            self.factory.clone(),
        )
        .await
    }
}
