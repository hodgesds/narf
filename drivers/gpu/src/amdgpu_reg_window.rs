//! The register window the Navi22 display owners share.
//!
//! Every DCN, DCCG, DIO, HUBBUB, DAL-mailbox and VBIOS-table owner reaches
//! the GPU through the same BAR5 mapping. In production a [`Window`] is that
//! mapping and nothing else: `read32`/`write32` are the `MmioRegion`
//! accessors. Kernel-test builds can attach one register model to a mapping
//! (keyed by its virtual address), so a single fake observes every block's
//! accesses in global order — which is how the end-to-end modeset model
//! checks the sequence against Linux without per-block fakes.
use narf_bus::MmioRegion;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Window(MmioRegion);
impl Window {
    pub(crate) const fn new(regs: MmioRegion) -> Self {
        Self(regs)
    }
    pub(crate) fn len(&self) -> u64 {
        self.0.len
    }
    /// # Safety
    /// As [`MmioRegion::read32`]: `offset + 4 <= len` and the device tolerates
    /// the read.
    #[inline]
    pub(crate) unsafe fn read32(&self, offset: u64) -> u32 {
        #[cfg(feature = "kernel-test")]
        if let Some(value) = model::read(self.0.virt, offset) {
            return value;
        }
        // SAFETY: forwarded caller contract.
        unsafe { self.0.read32(offset) }
    }
    /// # Safety
    /// As [`MmioRegion::write32`].
    #[inline]
    pub(crate) unsafe fn write32(&self, offset: u64, value: u32) {
        #[cfg(feature = "kernel-test")]
        if model::write(self.0.virt, offset, value) {
            return;
        }
        // SAFETY: forwarded caller contract.
        unsafe { self.0.write32(offset, value) }
    }
}

/// Test-only register models attached to a mapping's virtual address.
#[cfg(feature = "kernel-test")]
pub(crate) mod model {
    use alloc::{sync::Arc, vec::Vec};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use narf_lib::sync::IrqSafeSpinLock;

    /// A device model. Called with no window lock held; it must not reach
    /// back into a `Window`.
    pub(crate) trait Device: Send + Sync {
        fn read(&self, offset: u64) -> u32;
        fn write(&self, offset: u64, value: u32);
    }
    static ATTACHED: AtomicUsize = AtomicUsize::new(0);
    static MODELS: IrqSafeSpinLock<Vec<(u64, Arc<dyn Device>)>> = IrqSafeSpinLock::new(Vec::new());

    fn find(virt: u64) -> Option<Arc<dyn Device>> {
        if ATTACHED.load(Ordering::Acquire) == 0 {
            return None;
        }
        MODELS
            .lock()
            .iter()
            .find(|(v, _)| *v == virt)
            .map(|(_, d)| d.clone())
    }
    pub(super) fn read(virt: u64, offset: u64) -> Option<u32> {
        find(virt).map(|d| d.read(offset))
    }
    pub(super) fn write(virt: u64, offset: u64, value: u32) -> bool {
        find(virt).map(|d| d.write(offset, value)).is_some()
    }
    /// Routes every `Window` over a mapping at `virt` to `device` until dropped.
    pub(crate) struct Attached(u64);
    pub(crate) fn attach(virt: u64, device: Arc<dyn Device>) -> Attached {
        let mut models = MODELS.lock();
        assert!(
            models.iter().all(|(v, _)| *v != virt),
            "mapping already modelled"
        );
        models.push((virt, device));
        ATTACHED.fetch_add(1, Ordering::Release);
        Attached(virt)
    }
    impl Drop for Attached {
        fn drop(&mut self) {
            MODELS.lock().retain(|(v, _)| *v != self.0);
            ATTACHED.fetch_sub(1, Ordering::Release);
        }
    }
}
