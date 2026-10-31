//! JPEG's boot/recovery proof cycle under the retained shared-media owner.
use super::*;
use crate::amdgpu_jpeg_navi48 as jpeg;
impl Hardware {
    /// # Safety
    /// OWNER excludes clients/PM/reset, VCN retains the shared NBIO range,
    /// and the independent IH worker/CPU route stay active. Retain every
    /// owner after error/cancellation; only a full-device reset may recover
    /// when this extra live JPEG registration has not proved retirement.
    /// With `keep`, the drained ring stays registered and powered for
    /// clients; a retained registration is accepted only for that client
    /// ring after `retire_client_jpeg` proved its retirement.
    pub(crate) async unsafe fn prove_jpeg(
        &mut self,
        doorbells: narf_bus::MmioRegion,
        decode: bool,
        keep: bool,
    ) -> Result<jpeg::Proof, Error> {
        let retained = self.jpeg_owner.is_some();
        if retained
            && !(keep
                && self
                    .jpeg
                    .as_ref()
                    .is_some_and(|j| j.state() == jpeg::State::Stopped))
        {
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
            if !retained {
                self.jpeg_owner = Some(
                    dispatch::register(dispatch::Owner {
                        key: dispatch::Key::Jpeg { instance: 0 },
                        vmid: 0,
                        pasid: 0,
                    })
                    .map_err(|_| Error::Interrupts(ih::Error::Busy))?,
                );
            }
            // SAFETY: exclusive JPEG lifetime; no address was submitted yet
            // (or the client ring's retirement was proved before power-down).
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
            let mut proof = unsafe { jpeg.prove().await }.map_err(Error::Jpeg)?;
            if decode {
                // SAFETY: same registered exclusive kernel-VMID0 owner and
                // drained transport; retain the picture arena on cancellation.
                proof = unsafe { jpeg.prove_decode().await }
                    .map_err(Error::Jpeg)?
                    .completion;
            }
            if keep {
                // SAFETY: proofs drained the ring; the registration, power,
                // VCN range and GMC stay retained while clients may publish.
                unsafe { jpeg.open_clients() }.map_err(Error::Jpeg)?;
                return Ok(proof);
            }
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
    /// Close JPEG client publication and prove retirement of a possibly hung
    /// ring: JMI reset with clean DMA, then PowerDownJpeg. The dispatch
    /// registration stays live for the following in-place re-proof.
    /// # Safety
    /// OWNER excludes publishers/PM, the JPEG ledger is frozen, and every
    /// pending job's mappings and staged slot remain retained afterwards.
    pub(crate) async unsafe fn retire_client_jpeg(&mut self) -> Result<(), Error> {
        self.begin_media_use(true).await?;
        self.static_media_power().await?;
        if self.jpeg_owner.is_none() || !self.media_jpeg_clients {
            return Err(Error::Busy);
        }
        self.jpeg_test = Some(Err(Error::Busy));
        let jpeg = self.jpeg.as_mut().ok_or(Error::Invalid)?;
        // SAFETY: all publishers excluded; resources retained on failure.
        unsafe { jpeg.reset_stop().await }.map_err(Error::Jpeg)?;
        // SAFETY: JMI reset and power gating proved JRBC/decoder retirement.
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
        Ok(())
    }
}
