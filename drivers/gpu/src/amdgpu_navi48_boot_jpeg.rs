//! JPEG's boot/recovery proof cycle under the retained shared-media owner.
use super::*;
use crate::amdgpu_jpeg_navi48 as jpeg;
impl Hardware {
    /// # Safety
    /// OWNER excludes clients/PM/reset, VCN retains the shared NBIO range,
    /// and the independent IH worker/CPU route stay active. Retain every
    /// owner after error/cancellation; only a full-device reset may recover
    /// when this extra live JPEG registration has not proved retirement.
    pub(crate) async unsafe fn prove_jpeg(
        &mut self,
        doorbells: narf_bus::MmioRegion,
    ) -> Result<jpeg::Proof, Error> {
        if self.jpeg_owner.is_some() {
            return Err(Error::Busy);
        }
        self.jpeg_test = Some(Err(Error::Busy));
        let result = async {
            if self.jpeg.is_none() {
                // SAFETY: same retained GPU/GMC/VRAM pool and media range.
                self.jpeg = Some(
                    unsafe { jpeg::Jpeg::new(&self.gpu, self.authority, &self.pool, doorbells) }
                        .map_err(Error::Jpeg)?,
                );
            }
            self.jpeg_owner = Some(
                dispatch::register(dispatch::Owner {
                    key: dispatch::Key::Jpeg { instance: 0 },
                    vmid: 0,
                    pasid: 0,
                })
                .map_err(|_| Error::Interrupts(ih::Error::Busy))?,
            );
            // SAFETY: exclusive JPEG lifetime; no address was submitted yet.
            let power = unsafe {
                self.smu
                    .as_mut()
                    .ok_or(Error::Invalid)?
                    .set_jpeg_power(true)
                    .await
            }
            .map_err(Error::Smu)?;
            self.power = Some(power);
            let jpeg = self.jpeg.as_mut().ok_or(Error::Invalid)?;
            // SAFETY: matching power/GMC/range and retained IRQ registration.
            unsafe { jpeg.start(power).await }.map_err(Error::Jpeg)?;
            // SAFETY: registered kernel context, exclusive transport and CPU IRQs.
            let proof = unsafe { jpeg.prove().await }.map_err(Error::Jpeg)?;
            // SAFETY: proof drained its commands; all clients remain excluded.
            unsafe { jpeg.stop().await }.map_err(Error::Jpeg)?;
            // SAFETY: JRBC/JMI writes retired before static domain power-down.
            self.power = Some(
                unsafe {
                    self.smu
                        .as_mut()
                        .ok_or(Error::Invalid)?
                        .set_jpeg_power(false)
                        .await
                }
                .map_err(Error::Smu)?,
            );
            dispatch::retire(self.jpeg_owner.ok_or(Error::Invalid)?)
                .map_err(|_| Error::Interrupts(ih::Error::Protocol))?;
            self.jpeg_owner = None;
            Ok(proof)
        }
        .await;
        self.jpeg_test = Some(result);
        result
    }
}
