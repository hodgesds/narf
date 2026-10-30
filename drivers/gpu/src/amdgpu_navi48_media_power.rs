//! PSP14 SRAM transport shared by VCN5 and JPEG5, with no RDNA2 fallback.
pub(crate) trait Sram {
    async fn load(
        &mut self,
        jpeg: bool,
        words: &[u32],
    ) -> Result<(), crate::amdgpu_psp_ring::Error>;
}
impl Sram for crate::amdgpu_psp_ring::Psp {
    async fn load(
        &mut self,
        jpeg: bool,
        words: &[u32],
    ) -> Result<(), crate::amdgpu_psp_ring::Error> {
        self.load_media_sram5(jpeg, words).await
    }
}
pub(crate) const FEATURES: u64 = (1 << 20) | (1 << 44); // MM_DPM, DS_VCN
static ENABLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(true);
/// Boot policy; call before constructing the native RDNA4 owner.
pub fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, core::sync::atomic::Ordering::Release);
}
pub(crate) fn enabled() -> bool {
    ENABLED.load(core::sync::atomic::Ordering::Acquire)
}

#[cfg(feature = "kernel-test")]
pub(crate) mod tests {
    use super::*;
    use crate::amdgpu_psp_ring::Error;
    use alloc::{sync::Arc, vec::Vec};
    pub type Program = Arc<narf_lib::sync::IrqSafeSpinLock<Option<Vec<u32>>>>;
    pub struct Transport {
        pub program: Program,
        pub images: Vec<(bool, Vec<u32>)>,
        pub stall: bool,
        pub error: Option<Error>,
        pub revoke:
            Option<narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>>,
    }
    impl Transport {
        pub fn new(program: Program) -> Self {
            Self {
                program,
                images: Vec::new(),
                stall: false,
                error: None,
                revoke: None,
            }
        }
    }
    impl Sram for Transport {
        async fn load(&mut self, jpeg: bool, words: &[u32]) -> Result<(), Error> {
            self.images.push((jpeg, words.to_vec()));
            if self.stall {
                core::future::pending::<()>().await;
            }
            if let Some(error) = self.error {
                return Err(error);
            }
            if let Some(cap) = self.revoke {
                cap.revoke();
            }
            *self.program.lock() = Some(words.to_vec());
            Ok(())
        }
    }
}

#[cfg(feature = "kernel-test")]
impl Sram for () {
    async fn load(&mut self, _: bool, _: &[u32]) -> Result<(), crate::amdgpu_psp_ring::Error> {
        Err(crate::amdgpu_psp_ring::Error::Unsupported)
    }
}
