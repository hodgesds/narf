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
    pub(crate) fn media_hevc_decode_result(&self) -> Option<Result<vcn::DecodeProof, vcn::Error>> {
        self.sequence.backend.vcn.as_ref()?.hevc_result()
    }
    pub(crate) fn media_hevc10_decode_result(
        &self,
    ) -> Option<Result<vcn::DecodeProof, vcn::Error>> {
        self.sequence.backend.vcn.as_ref()?.hevc10_result()
    }
    pub(crate) fn media_vp9_decode_result(&self) -> Option<Result<vcn::DecodeProof, vcn::Error>> {
        self.sequence.backend.vcn.as_ref()?.vp9_result()
    }
    pub(crate) fn media_vp9_10_decode_result(
        &self,
    ) -> Option<Result<vcn::DecodeProof, vcn::Error>> {
        self.sequence.backend.vcn.as_ref()?.vp9_10_result()
    }
    pub(crate) fn media_av1_decode_result(&self) -> Option<Result<vcn::DecodeProof, vcn::Error>> {
        self.sequence.backend.vcn.as_ref()?.av1_result()
    }
    pub(crate) fn media_av1_10_decode_result(
        &self,
    ) -> Option<Result<vcn::DecodeProof, vcn::Error>> {
        self.sequence.backend.vcn.as_ref()?.av1_10_result()
    }
    pub(crate) fn media_encode_result(&self) -> Option<Result<vcn::EncodeProof, vcn::Error>> {
        self.sequence.backend.vcn.as_ref()?.encode_result()
    }
    pub(crate) fn media_av1_encode_result(
        &self,
    ) -> Option<Result<vcn::EncodeRoundtripProof, vcn::Error>> {
        self.sequence.backend.vcn.as_ref()?.av1_encode_result()
    }
    pub(crate) fn media_hevc_encode_result(
        &self,
    ) -> Option<Result<vcn::EncodeRoundtripProof, vcn::Error>> {
        self.sequence.backend.vcn.as_ref()?.hevc_encode_result()
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
    pub(crate) fn media_jpeg_decode_result(
        &self,
    ) -> Option<Result<crate::amdgpu_jpeg_navi48::DecodeProof, crate::amdgpu_jpeg_navi48::Error>>
    {
        self.sequence.backend.jpeg.as_ref()?.decode_result()
    }
    /// Transactionally admit all requested retained media backing before the
    /// startup worker or a client heap can consume this owner pool. No power
    /// message, registration or hardware address is published on refusal.
    /// # Safety
    /// Same retained exclusive GPU/GMC/firmware owner as prove_media_transport.
    pub(crate) unsafe fn prepare_media_transport(
        &mut self,
        keep: bool,
        decode: bool,
        encode: bool,
        jpeg: bool,
        jpeg_decode: bool,
    ) -> Result<(), Error> {
        if self.state() != State::MemoryReady {
            return Err(Error::Busy);
        }
        let request = MediaRequest::new(keep, decode, encode, jpeg, jpeg_decode);
        let hw = &mut self.sequence.backend;
        if let Some(old) = hw.media_request {
            return if old == request {
                Ok(())
            } else {
                Err(Error::Busy)
            };
        }
        if hw.media_test.is_some() || hw.vcn.is_some() || hw.jpeg.is_some() {
            return Err(Error::Busy);
        }
        if hw.pool.available() < request.bytes() {
            return Err(Error::Allocation);
        }
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
        // SAFETY: the retained exclusive device owns its mapped doorbells;
        // constructors perform bounded validation and unpublished allocation.
        let doorbells =
            unsafe { mes::map_doorbells(&hw.pci, &hw.authority) }.map_err(Error::Mes)?;
        // SAFETY: matching retained firmware/GMC/pool; no media publisher exists.
        let mut vcn = unsafe {
            vcn::Vcn::new(
                &hw.gpu,
                hw.authority,
                &hw.pool,
                doorbells,
                bytes,
                image.version(),
            )
        }
        .map_err(Error::Vcn)?;
        vcn.reserve_proofs(request.ibs(), request.decode, request.encode)
            .map_err(Error::Vcn)?;
        let jpeg = if request.jpeg {
            // SAFETY: same exclusive device/pool; all allocations stay local
            // and unpublished until BOTH engines' complete request fits.
            let mut jpeg = unsafe {
                crate::amdgpu_jpeg_navi48::Jpeg::new(&hw.gpu, hw.authority, &hw.pool, doorbells)
            }
            .map_err(Error::Jpeg)?;
            jpeg.reserve_proofs(request.jpeg_decode, request.keep)
                .map_err(Error::Jpeg)?;
            Some(jpeg)
        } else {
            None
        };
        hw.vcn = Some(vcn);
        hw.jpeg = jpeg;
        hw.media_request = Some(request);
        Ok(())
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
        jpeg_decode: bool,
    ) -> Result<vcn::InterruptProof, Error> {
        if self.state() != State::MemoryReady || self.sequence.backend.media_test.is_some() {
            return Err(Error::Busy);
        }
        // SAFETY: caller retains the same exclusive native owner. This is
        // idempotent for the early startup claim and covers new resume owners.
        unsafe { self.prepare_media_transport(keep_running, decode, encode, jpeg, jpeg_decode) }?;
        let hw = &mut self.sequence.backend;
        // Written before the first await, so cancellation keeps all three
        // client submit wrappers closed even if the VCPU never started.
        hw.media_test = Some(Err(Error::Busy));
        hw.media_decode_required = decode;
        hw.media_encode_required = encode;
        // Client media publishes JPEG0 beside the unified VCN queue.
        let jpeg = jpeg || jpeg_decode || keep_running;
        hw.media_jpeg_required = jpeg;
        hw.media_jpeg_clients = keep_running;
        hw.media_jpeg_decode_required = jpeg_decode;
        let result = async {
            // SAFETY: preparation validated this owner's doorbell mapping;
            // no competing media/reset/PM writer exists throughout this task.
            let doorbells =
                unsafe { mes::map_doorbells(&hw.pci, &hw.authority) }.map_err(Error::Mes)?;
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
                unsafe { vcn.prove_decode().await }.map_err(Error::Vcn)?;
                // SAFETY: the AVC proof drained the same retained transport;
                // clients remain excluded through this independent Main8 proof.
                unsafe { vcn.prove_hevc().await }.map_err(Error::Vcn)?;
                // SAFETY: no client publication; fresh drained Main8 transport.
                unsafe { vcn.prove_hevc10().await }.map_err(Error::Vcn)?;
                // SAFETY: retained kernel VMID0 and drained Main10 predecessor.
                unsafe { vcn.prove_vp9().await }.map_err(Error::Vcn)?;
                // SAFETY: retained VMID0 and drained Profile0 predecessor.
                unsafe { vcn.prove_vp9_10().await }.map_err(Error::Vcn)?;
                // SAFETY: retained VMID0 and drained Profile2 predecessor.
                unsafe { vcn.prove_av1().await }.map_err(Error::Vcn)?;
                // SAFETY: retained VMID0 and drained AV1 Main8 predecessor;
                // clients remain excluded through the full P010 precision proof.
                proof = unsafe { vcn.prove_av1_10().await }
                    .map_err(Error::Vcn)?
                    .completion;
            }
            if encode {
                // SAFETY: same exclusive retained transport and kernel VMID0;
                // no client can publish before this requested proof finishes.
                unsafe { vcn.prove_encode().await }.map_err(Error::Vcn)?;
                // SAFETY: same retained owner; exact encode output remains pinned
                // through the independent decoder and per-component fidelity check.
                unsafe { vcn.prove_hevc_encode().await }.map_err(Error::Vcn)?;
                // SAFETY: same retained native owner; both AV1 arenas remain
                // published through encode, fresh decode and fidelity validation.
                proof = unsafe { vcn.prove_av1_encode().await }
                    .map_err(Error::Vcn)?
                    .decoded
                    .completion;
            }
            if jpeg {
                // SAFETY: VCN retains the shared media range and GMC, no
                // clients can publish, and IH/CPU delivery remains active.
                unsafe { hw.prove_jpeg(doorbells, jpeg_decode, keep_running).await }?;
            }
            if keep_running {
                hw.configure_media_power().await?;
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
