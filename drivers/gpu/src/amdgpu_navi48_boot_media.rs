//! Optional retained VCN5 transport/power cycle before publishing client work.
use super::*;
use crate::amdgpu_vcn_navi48 as vcn;

impl ColdBoot {
    pub(crate) fn media_submission_ready(&self) -> bool {
        self.sequence
            .backend
            .media_test
            .as_ref()
            .is_none_or(Result::is_ok)
    }
    pub(crate) fn media_result(&self) -> Option<Result<vcn::Proof, Error>> {
        self.sequence.backend.media_test
    }
    /// # Safety
    /// OWNER excludes every engine/PM/firmware user, no client job or clear
    /// has been published, and this is the retained post-interrupt-proof GPU.
    /// Any cancellation/failure requires explicit whole-device recovery.
    pub(crate) async unsafe fn prove_media_transport(&mut self) -> Result<vcn::Proof, Error> {
        if self.state() != State::MemoryReady || self.sequence.backend.media_test.is_some() {
            return Err(Error::Busy);
        }
        let hw = &mut self.sequence.backend;
        // Written before the first await, so cancellation keeps all three
        // client submit wrappers closed even if the VCPU never started.
        hw.media_test = Some(Err(Error::Busy));
        let result = async {
            let image = hw
                .firmware
                .gfx
                .images()
                .map_err(Error::Firmware)?
                .into_iter()
                .zip(gfx::Source::ALL)
                .find(|(_, source)| *source == gfx::Source::Vcn)
                .ok_or(Error::Invalid)?
                .0;
            let bytes = image.payloads().next().ok_or(Error::Invalid)?.bytes().len();
            // SAFETY: same exclusively retained PCI function and BAR2.
            let doorbells =
                unsafe { mes::map_doorbells(&hw.pci, &hw.authority) }.map_err(Error::Mes)?;
            // SAFETY: retained matching pool/firmware/GMC and exclusive media
            // range. Store the owner before any power-up or VCPU publication.
            hw.vcn = Some(
                unsafe { vcn::Vcn::new(&hw.gpu, hw.authority, &hw.pool, doorbells, bytes) }
                    .map_err(Error::Vcn)?,
            );
            let smu = hw.smu.as_mut().ok_or(Error::Invalid)?;
            // SAFETY: no competing media owner or power writer.
            let power = unsafe { smu.set_vcn_power(true).await }.map_err(Error::Smu)?;
            hw.power = Some(power);
            let firmware = hw.psp.as_ref().ok_or(Error::Invalid)?.media_firmware();
            let vcn = hw.vcn.as_mut().ok_or(Error::Invalid)?;
            // SAFETY: SMU power-up completed; matching PSP TMR and GMC stay
            // alive and no client can access the ring or its backing memory.
            unsafe { vcn.start(firmware, power).await }.map_err(Error::Vcn)?;
            // SAFETY: same retained prerequisites and exclusive transport.
            let proof = unsafe { vcn.prove().await }.map_err(Error::Vcn)?;
            // SAFETY: no client publication; the proof drained its whole ring.
            unsafe { vcn.stop().await }.map_err(Error::Vcn)?;
            // SAFETY: stop proved VCPU/LMI retirement before domain power-down.
            hw.power = Some(unsafe { smu.set_vcn_power(false).await }.map_err(Error::Smu)?);
            Ok(proof)
        }
        .await;
        hw.media_test = Some(result);
        result
    }
}
