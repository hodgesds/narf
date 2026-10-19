//! Optional retained VCN5 transport/power cycle before publishing client work.
use super::*;
use crate::amdgpu_navi48_dispatch as dispatch;
use crate::amdgpu_vcn_navi48 as vcn;
#[path = "amdgpu_navi48_boot_jpeg.rs"]
mod jpeg_proof;

impl ColdBoot {
    pub(crate) fn media_submission_ready(&self) -> bool {
        self.sequence
            .backend
            .media_test
            .as_ref()
            .is_none_or(Result::is_ok)
    }
    pub(crate) fn media_result(&self) -> Option<Result<vcn::InterruptProof, Error>> {
        self.sequence.backend.media_test
    }
    pub(crate) fn media_state(&self) -> Option<vcn::State> {
        self.sequence.backend.vcn.as_ref().map(vcn::Vcn::state)
    }
    pub(crate) fn media_ib_result(&self) -> Option<Result<vcn::InterruptProof, vcn::Error>> {
        self.sequence.backend.vcn.as_ref()?.ib_result()
    }
    pub(crate) fn media_decode_result(&self) -> Option<Result<vcn::DecodeProof, vcn::Error>> {
        self.sequence.backend.vcn.as_ref()?.decode_result()
    }
    pub(crate) fn media_encode_result(&self) -> Option<Result<vcn::EncodeProof, vcn::Error>> {
        self.sequence.backend.vcn.as_ref()?.encode_result()
    }
    pub(crate) fn media_jpeg_result(
        &self,
    ) -> Option<Result<crate::amdgpu_jpeg_navi48::Proof, Error>> {
        self.sequence.backend.jpeg_test
    }
    pub(crate) fn media_jpeg_state(&self) -> Option<crate::amdgpu_jpeg_navi48::State> {
        self.sequence
            .backend
            .jpeg
            .as_ref()
            .map(crate::amdgpu_jpeg_navi48::Jpeg::state)
    }
    /// # Safety
    /// OWNER excludes every engine/PM/firmware user, no client job or clear
    /// has been published, and this is the retained post-interrupt-proof GPU.
    /// Any cancellation/failure requires explicit whole-device recovery.
    pub(crate) async unsafe fn prove_media_transport(
        &mut self,
        keep_running: bool,
        decode: bool,
        encode: bool,
        jpeg: bool,
    ) -> Result<vcn::InterruptProof, Error> {
        if self.state() != State::MemoryReady || self.sequence.backend.media_test.is_some() {
            return Err(Error::Busy);
        }
        let hw = &mut self.sequence.backend;
        // Written before the first await, so cancellation keeps all three
        // client submit wrappers closed even if the VCPU never started.
        hw.media_test = Some(Err(Error::Busy));
        hw.media_decode_required = decode;
        hw.media_encode_required = encode;
        hw.media_jpeg_required = jpeg;
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
            // SAFETY: no competing media owner or power writer.
            let power = unsafe {
                hw.smu
                    .as_mut()
                    .ok_or(Error::Invalid)?
                    .set_vcn_power(true)
                    .await
            }
            .map_err(Error::Smu)?;
            hw.power = Some(power);
            let firmware = hw.psp.as_ref().ok_or(Error::Invalid)?.media_firmware();
            let vcn = hw.vcn.as_mut().ok_or(Error::Invalid)?;
            // SAFETY: SMU power-up completed; matching PSP TMR and GMC stay
            // alive and no client can access the ring or its backing memory.
            unsafe { vcn.start(firmware, power).await }.map_err(Error::Vcn)?;
            // SAFETY: same retained prerequisites and exclusive transport.
            unsafe { vcn.prove().await }.map_err(Error::Vcn)?;
            // Retain the registration before enabling the VCPU master IRQ.
            // Failure/cancellation leaves the extra owner live, so the
            // three-queue fault re-arm path cannot assume media quiescence.
            hw.vcn_owner = Some(
                dispatch::register(dispatch::Owner {
                    key: dispatch::Key::Vcn { instance: 0 },
                    vmid: 0,
                    pasid: 0,
                })
                .map_err(|_| Error::Interrupts(ih::Error::Busy))?,
            );
            // SAFETY: matching retained registration, independent IH service,
            // drained kernel transport, exclusive OWNER and enabled CPU IRQs.
            let mut proof = unsafe { vcn.prove_interrupts().await }.map_err(Error::Vcn)?;
            if keep_running || decode || encode || jpeg {
                // SAFETY: no client publication yet; matching kernel VMID0,
                // retained firmware and live registered source owner.
                proof = unsafe { vcn.prove_ibs().await }.map_err(Error::Vcn)?;
            }
            if decode {
                // SAFETY: same retained kernel VMID0/firmware/source owner,
                // no intervening client publication and a drained IB proof.
                proof = unsafe { vcn.prove_decode().await }
                    .map_err(Error::Vcn)?
                    .completion;
            }
            if encode {
                // SAFETY: same exclusive retained transport and kernel VMID0;
                // no client can publish before this requested proof finishes.
                proof = unsafe { vcn.prove_encode().await }
                    .map_err(Error::Vcn)?
                    .completion;
            }
            if jpeg {
                // SAFETY: VCN retains the shared media range and GMC, no
                // clients can publish, and IH/CPU delivery remains active.
                unsafe { hw.prove_jpeg(doorbells).await }?;
            }
            if keep_running {
                return Ok(proof);
            }
            // SAFETY: no client publication; the proof drained its whole ring.
            unsafe { hw.vcn.as_mut().ok_or(Error::Invalid)?.stop().await }.map_err(Error::Vcn)?;
            // SAFETY: stop proved VCPU/LMI retirement before domain power-down.
            hw.power = Some(
                unsafe {
                    hw.smu
                        .as_mut()
                        .ok_or(Error::Invalid)?
                        .set_vcn_power(false)
                        .await
                }
                .map_err(Error::Smu)?,
            );
            let handle = hw.vcn_owner.ok_or(Error::Invalid)?;
            dispatch::retire(handle).map_err(|_| Error::Interrupts(ih::Error::Protocol))?;
            hw.vcn_owner = None;
            Ok(proof)
        }
        .await;
        hw.media_test = Some(result);
        result
    }
}
