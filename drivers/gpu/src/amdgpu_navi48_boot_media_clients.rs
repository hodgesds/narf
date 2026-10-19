//! Retained media client publication and reset phases under the platform owner.
use super::*;
use crate::{amdgpu_navi48_dispatch as dispatch, amdgpu_vcn_navi48 as vcn};

impl ColdBoot {
    pub(crate) fn client_media_fence_reader(&self) -> Option<vcn::FenceReader> {
        let hw = &self.sequence.backend;
        if !self.media_submission_ready() || hw.vcn_owner.is_none() {
            return None;
        }
        let vcn = hw.vcn.as_ref()?;
        vcn.ib_result()?.ok()?;
        if hw.media_decode_required {
            vcn.decode_result()?.ok()?;
        }
        if hw.media_encode_required {
            vcn.encode_result()?.ok()?;
        }
        vcn.fence_reader()
    }
    pub(crate) fn client_media_owner(&self) -> Option<dispatch::Handle> {
        self.sequence.backend.vcn_owner
    }
    /// # Safety
    /// A coordinated recovery receipt retired every owned queue and renewed
    /// this media registration. OWNER excludes all submissions and PM writers.
    pub(crate) unsafe fn media_rearmed(&mut self, handle: dispatch::Handle) {
        let hw = &mut self.sequence.backend;
        assert!(hw.vcn_owner.is_some());
        hw.vcn_owner = Some(handle);
    }
    /// # Safety
    /// OWNER serializes publication. The caller lends a distinct MMHUB VMID
    /// and retains this job's complete VM/BO backing until its translated
    /// fence passes or a reset proves the engine cannot access it again.
    pub(crate) unsafe fn submit_client_media_job(
        &mut self,
        job: crate::amdgpu_gfx12_queue::Job,
    ) -> Result<u32, vcn::Error> {
        if self.state() != State::MemoryReady
            || !self.media_submission_ready()
            || crate::amdgpu_navi48_interrupts::blocked()
            || self.sequence.backend.vcn_owner.is_none()
        {
            return Err(vcn::Error::Busy);
        }
        let vcn = self.sequence.backend.vcn.as_mut().ok_or(vcn::Error::Busy)?;
        if !matches!(
            vcn.state(),
            vcn::State::IbVerified | vcn::State::DecodeVerified | vcn::State::EncodeVerified
        ) {
            return Err(vcn::Error::Busy);
        }
        // SAFETY: the caller supplies the owned MMHUB binding and resources.
        unsafe { vcn.submit(job) }
    }
    /// # Safety
    /// OWNER excludes all client/clear/reset/PM writers. All ledgers are
    /// frozen; all pending media contexts are cancelled before entering.
    /// Retain every allocation through failure or cancellation. A successful
    /// return proves old media work retired, but does not permit replay or
    /// retirement until global re-arm and a fresh media interrupt proof.
    pub(crate) async unsafe fn retire_client_media(&mut self) -> Result<(), Error> {
        if self.sequence.backend.vcn_owner.is_none() {
            return Err(Error::Busy);
        }
        let hw = &mut self.sequence.backend;
        hw.media_test = Some(Err(Error::Busy));
        let vcn = hw.vcn.as_mut().ok_or(Error::Invalid)?;
        let smu = hw.smu.as_mut().ok_or(Error::Invalid)?;
        // SAFETY: all publishers are excluded and pending resources remain
        // retained. Failure to drain/idle requires whole-device recovery.
        unsafe { vcn.stop().await }.map_err(Error::Vcn)?;
        // SAFETY: VCPU/LMI retirement precedes static domain power-down.
        hw.power = Some(unsafe { smu.set_vcn_power(false).await }.map_err(Error::Smu)?);
        // SAFETY: exclusive static media owner, no concurrent PM transition.
        let power = unsafe { smu.set_vcn_power(true).await }.map_err(Error::Smu)?;
        hw.power = Some(power);
        let firmware = hw.psp.as_ref().ok_or(Error::Invalid)?.media_firmware();
        // SAFETY: retained PSP TMR/GMC, power and backing on the same GPU.
        // Restart clears codec context; no old media job may be replayed.
        unsafe { vcn.start(firmware, power).await }.map_err(Error::Vcn)?;
        // SAFETY: exclusive restarted ring and retained firmware windows.
        unsafe { vcn.prove().await }.map_err(Error::Vcn)?;
        Ok(())
    }
    /// # Safety
    /// OWNER retains the restarted media ring and its renewed interrupt
    /// registration. All ledgers stay frozen until this proof and every
    /// healthy graphics/compute/SDMA replay complete publication.
    pub(crate) async unsafe fn reprove_client_media(
        &mut self,
    ) -> Result<vcn::InterruptProof, Error> {
        let hw = &mut self.sequence.backend;
        if hw.vcn_owner.is_none() {
            return Err(Error::Busy);
        }
        hw.media_test = Some(Err(Error::Busy));
        let decode = hw.media_decode_required;
        let encode = hw.media_encode_required;
        let jpeg = hw.media_jpeg_required;
        // SAFETY: coordinated re-arm completed, media registration retained,
        // native transport drained and independent IH service remains active.
        let result = async {
            let vcn = hw.vcn.as_mut().ok_or(Error::Invalid)?;
            // SAFETY: same renewed owner and exclusively retained transport.
            unsafe { vcn.prove_interrupts().await }.map_err(Error::Vcn)?;
            // SAFETY: ring drained, no client replay and kernel VMID0 retained.
            let mut proof = unsafe { vcn.prove_ibs().await }.map_err(Error::Vcn)?;
            if decode {
                // SAFETY: same retained kernel VMID0 and no replay until the
                // requested picture proof and all other rings finish.
                proof = unsafe { vcn.prove_decode().await }
                    .map_err(Error::Vcn)?
                    .completion;
            }
            if encode {
                // SAFETY: all ledgers remain frozen, including media, until
                // the new requested proof and every healthy replay finish.
                proof = unsafe { vcn.prove_encode().await }
                    .map_err(Error::Vcn)?
                    .completion;
            }
            if jpeg {
                // SAFETY: same owned PCI function and BAR2, all client
                // ledgers frozen; VCN retains the shared range until JPEG stops.
                let doorbells =
                    unsafe { mes::map_doorbells(&hw.pci, &hw.authority) }.map_err(Error::Mes)?;
                // SAFETY: registered media, retained GMC and active IH route.
                unsafe { hw.prove_jpeg(doorbells).await }?;
            }
            Ok(proof)
        }
        .await;
        hw.media_test = Some(result);
        result
    }
    /// # Safety
    /// OWNER excludes all publishers/PM and the media ledger is frozen with
    /// every old media context cancelled. Keep its resources retained until
    /// the caller commits retirement after both new native proofs.
    pub(crate) async unsafe fn recover_client_media(&mut self) -> Result<u32, Error> {
        // SAFETY: same exclusive retained owner and cancelled media ledger.
        unsafe { self.retire_client_media().await }?;
        // SAFETY: the IH service stayed armed during this queue-only reset;
        // its retained registration and new transport now support the proof.
        let proof = unsafe { self.reprove_client_media().await }?;
        Ok(proof.fence.sequence)
    }
}
