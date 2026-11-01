// SPDX-License-Identifier: GPL-2.0-or-later
//! A sealed native EU20/40 program is minted only after parked real I/O and
//! literal gain/BB/RF readback. Geometry and signed bytes alone cannot mint it.
use super::ht40_geometry::Geometry;
use super::ht40_qualification::Gains;
use super::{ControlIo, Error, Owner, WideQualification};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use core::{future::Future, task::Poll};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtl8xxxu) enum Mode {
    Twenty,
    Forty,
}
#[derive(Clone)]
pub(in crate::rtl8xxxu) struct Plan {
    qualification: Arc<WideQualification>,
    mode: Mode,
}
impl Plan {
    pub(in crate::rtl8xxxu) fn new(qualification: Arc<WideQualification>, mode: Mode) -> Self {
        Self {
            qualification,
            mode,
        }
    }
    pub(in crate::rtl8xxxu) fn narrow(&self) -> Self {
        Self {
            qualification: self.qualification.clone(),
            mode: Mode::Twenty,
        }
    }
    pub(in crate::rtl8xxxu) fn geometry(&self) -> Geometry {
        self.qualification.geometry()
    }
    pub(in crate::rtl8xxxu) fn mode(&self) -> Mode {
        self.mode
    }
    pub(in crate::rtl8xxxu) fn current(&self) -> Result<(), Error> {
        self.qualification.gains().map(|_| ())
    }
    pub(in crate::rtl8xxxu) async fn fence<T>(
        &self,
        future: impl Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        let gains = self.qualification.gains()?;
        let mut future = core::pin::pin!(future);
        core::future::poll_fn(|cx| {
            self.qualification
                .invoke(gains, || future.as_mut().poll(cx))
                .unwrap_or_else(|e| Poll::Ready(Err(e)))
        })
        .await
    }
}
#[derive(Clone)]
pub(in crate::rtl8xxxu) struct Program {
    plan: Plan,
    gains: Gains,
    valid: Arc<AtomicBool>,
}
impl Program {
    pub(in crate::rtl8xxxu) fn plan(&self) -> Plan {
        self.plan.clone()
    }
    pub(in crate::rtl8xxxu) fn legacy_gains(&self) -> (u8, u8) {
        (self.gains.cck(), self.gains.ofdm())
    }
    pub(in crate::rtl8xxxu) fn geometry(&self) -> Geometry {
        self.plan.geometry()
    }
    pub(in crate::rtl8xxxu) fn mode(&self) -> Mode {
        self.plan.mode
    }
    pub(in crate::rtl8xxxu) fn invoke<T>(&self, op: impl FnOnce() -> T) -> Result<T, Error> {
        if !self.valid.load(Ordering::Acquire) {
            return Err(Error::Policy);
        }
        let result = self.plan.qualification.invoke(self.gains, op);
        if result.is_err() {
            self.valid.store(false, Ordering::Release);
        }
        result
    }
    async fn fence<T>(&self, future: impl Future<Output = Result<T, Error>>) -> Result<T, Error> {
        let mut future = core::pin::pin!(future);
        core::future::poll_fn(|cx| {
            self.invoke(|| future.as_mut().poll(cx))
                .unwrap_or_else(|e| Poll::Ready(Err(e)))
        })
        .await
    }
    pub(in crate::rtl8xxxu) async fn install<C: ControlIo>(
        firmware: &Owner<C>,
        plan: Plan,
    ) -> Result<Arc<Self>, Error> {
        if firmware.factory() != Some(plan.qualification.factory()) {
            return Err(Error::State);
        }
        let gains = plan.qualification.gains()?;
        let program = Self {
            plan,
            gains,
            valid: Arc::new(AtomicBool::new(true)),
        };
        struct Attempt<'a, C: ControlIo> {
            firmware: &'a Owner<C>,
            armed: bool,
        }
        impl<C: ControlIo> Drop for Attempt<'_, C> {
            fn drop(&mut self) {
                if self.armed {
                    self.firmware
                        .runtime_failed(super::super::firmware_transport::Error::Cancelled);
                }
            }
        }
        let mut attempt = Attempt {
            firmware,
            armed: true,
        };
        let result = program
            .fence(async {
                if firmware.read16(0x100).await.map_err(Error::Control)? & 0xc0 != 0 {
                    return Err(Error::State);
                }
                match program.mode() {
                    Mode::Twenty => super::super::channel_runtime::initial20(
                        firmware,
                        program.plan.qualification.factory(),
                        program.geometry().primary(),
                    )
                    .await
                    .map_err(Error::Control)?,
                    Mode::Forty => {
                        update8(firmware, 0x603, 4, 0).await?;
                        for reg in [0x800, 0x900] {
                            update32(firmware, reg, 1, 1).await?;
                        }
                        let g = program.geometry();
                        update32(firmware, 0x440, 3 << 21, g.response_subchannel()).await?;
                        update32(firmware, 0xa00, 1 << 4, g.cck_sideband()).await?;
                        update32(firmware, 0xd00, 3 << 10, g.ofdm_prime()).await?;
                        update32(firmware, 0x818, 3 << 26, g.fpga_secondary()).await?;
                        let rf = super::super::calibration::read_rf(firmware, 0x18)
                            .await
                            .map_err(Error::Control)?;
                        super::super::calibration::write_rf(firmware, 0x18, g.rf_mode(rf))
                            .await
                            .map_err(Error::Control)?;
                    }
                }
                for (reg, mask, value) in legacy(gains) {
                    update32(firmware, reg, mask, value).await?;
                }
                for (reg, row) in [0xe10, 0xe14].into_iter().zip(gains.mcs().chunks_exact(4)) {
                    update32(
                        firmware,
                        reg,
                        u32::MAX,
                        u32::from_le_bytes(row.try_into().unwrap()),
                    )
                    .await?;
                }
                let sifs = firmware.read16(0x428).await.map_err(Error::Control)?;
                firmware
                    .write16(0x428, (sifs & 0xff) | 0x1000)
                    .await
                    .map_err(Error::Control)?;
                program.readback_inner(firmware).await?;
                if firmware.read16(0x100).await.map_err(Error::Control)? & 0xc0 != 0 {
                    return Err(Error::State);
                }
                Ok(())
            })
            .await;
        attempt.armed = false;
        if let Err(error) = result {
            firmware.runtime_failed(super::super::firmware_transport::Error::Calibration);
            return Err(error);
        }
        Ok(Arc::new(program))
    }
    pub(in crate::rtl8xxxu) async fn readback<C: ControlIo>(
        &self,
        firmware: &Owner<C>,
    ) -> Result<(), Error> {
        if firmware.factory() != Some(self.plan.qualification.factory()) {
            return Err(Error::State);
        }
        let result = self.fence(self.readback_inner(firmware)).await;
        if result.is_err() {
            self.valid.store(false, Ordering::Release);
        }
        result
    }
    async fn readback_inner<C: ControlIo>(&self, firmware: &Owner<C>) -> Result<(), Error> {
        let geometry = self.geometry();
        let wide = self.mode() == Mode::Forty;
        if (firmware.read8(0x603).await.map_err(Error::Control)? & 4 == 0) != wide
            || (firmware.read32(0x800).await.map_err(Error::Control)? & 1 != 0) != wide
            || (firmware.read32(0x900).await.map_err(Error::Control)? & 1 != 0) != wide
            || firmware.read16(0x428).await.map_err(Error::Control)? >> 8 != 16
        {
            return Err(Error::State);
        }
        let rf = super::super::calibration::read_rf(firmware, 0x18)
            .await
            .map_err(Error::Control)?;
        let expected = if wide {
            u32::from(geometry.center()) | 0x400
        } else {
            u32::from(geometry.primary()) | 0xc00
        };
        if rf & 0xfff != expected {
            return Err(Error::State);
        }
        if wide {
            for (reg, mask, value) in [
                (0x440, 3 << 21, geometry.response_subchannel()),
                (0xa00, 1 << 4, geometry.cck_sideband()),
                (0xd00, 3 << 10, geometry.ofdm_prime()),
                (0x818, 3 << 26, geometry.fpga_secondary()),
            ] {
                if firmware.read32(reg).await.map_err(Error::Control)? & mask != value {
                    return Err(Error::State);
                }
            }
        }
        for (reg, mask, value) in legacy(self.gains) {
            if firmware.read32(reg).await.map_err(Error::Control)? & mask != value {
                return Err(Error::State);
            }
        }
        for (reg, row) in [0xe10, 0xe14]
            .into_iter()
            .zip(self.gains.mcs().chunks_exact(4))
        {
            if firmware.read32(reg).await.map_err(Error::Control)?
                != u32::from_le_bytes(row.try_into().unwrap())
            {
                return Err(Error::State);
            }
        }
        Ok(())
    }
    pub(in crate::rtl8xxxu) fn seal(self: &Arc<Self>) -> RxSeal {
        RxSeal(self.clone())
    }
}
fn legacy(gains: Gains) -> [(u16, u32, u32); 4] {
    [
        (0xe08, 0xff00, u32::from(gains.cck()) << 8),
        (0x86c, 0xffffff00, u32::from(gains.cck()) * 0x01010100),
        (0xe00, u32::MAX, u32::from(gains.ofdm()) * 0x01010101),
        (0xe04, u32::MAX, u32::from(gains.ofdm()) * 0x01010101),
    ]
}
async fn update8<C: ControlIo>(
    owner: &Owner<C>,
    reg: u16,
    mask: u8,
    bits: u8,
) -> Result<(), Error> {
    let previous = owner.read8(reg).await.map_err(Error::Control)?;
    let value = (previous & !mask) | bits;
    owner.write8(reg, value).await.map_err(Error::Control)?;
    if owner.read8(reg).await.map_err(Error::Control)? != value {
        return Err(Error::State);
    }
    Ok(())
}
async fn update32<C: ControlIo>(
    owner: &Owner<C>,
    reg: u16,
    mask: u32,
    bits: u32,
) -> Result<(), Error> {
    let previous = owner.read32(reg).await.map_err(Error::Control)?;
    let value = (previous & !mask) | bits;
    owner.write32(reg, value).await.map_err(Error::Control)?;
    if owner.read32(reg).await.map_err(Error::Control)? != value {
        return Err(Error::State);
    }
    Ok(())
}
/// Only the actual Receiver installs this after a proved physical stream cut.
/// Raw RX width bits and ordinary callers cannot construct this sealed value.
#[derive(Clone)]
pub(in crate::rtl8xxxu) struct RxSeal(Arc<Program>);
impl RxSeal {
    pub(in crate::rtl8xxxu) fn admits(&self, wide: bool) -> bool {
        (!wide || self.0.mode() == Mode::Forty) && self.0.invoke(|| ()).is_ok()
    }
}
impl core::fmt::Debug for RxSeal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("EuNativeProgram")
            .field(&self.0.geometry())
            .field(&self.0.mode())
            .finish()
    }
}
impl PartialEq for RxSeal {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for RxSeal {}
