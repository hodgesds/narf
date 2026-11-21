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

const IDLE_NS: u64 = 1_000_000_000; // Linux VCN_IDLE_TIMEOUT

/// When the media idle supervisor looks again, in ns from `now`, given each
/// engine's (VCN, JPEG) last use and whether it is awake; `None`: not until
/// the next use. As Linux's idle work: the rest of VCN_IDLE_TIMEOUT after a
/// recent use, one timeout later while an engine stays awake past it, and
/// nothing for gated or absent engines.
pub(crate) fn next_idle_check(
    last_use: [Option<u64>; 2],
    awake: [bool; 2],
    now: u64,
) -> Option<u64> {
    (0..2)
        .filter(|&k| awake[k])
        .map(|k| {
            let since = last_use[k].map_or(0, |last| now.saturating_sub(last));
            if since < IDLE_NS {
                IDLE_NS - since
            } else {
                IDLE_NS
            }
        })
        .min()
}

/// The supervisor parked with every engine gated or absent.
static IDLE_PARKED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static IDLE_WAKER: narf_lib::sync::IrqSafeSpinLock<Option<core::task::Waker>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// A media engine is used (`begin_media_use`), or the supervisor must look
/// (stop): the parked supervisor runs again.
pub(crate) fn media_used() {
    IDLE_PARKED.store(false, core::sync::atomic::Ordering::Release);
    let waker = IDLE_WAKER.lock().take();
    if let Some(w) = waker {
        w.wake();
    }
}
/// Park the supervisor until the next [`media_used`]. Called under OWNER,
/// which `begin_media_use` also holds, so a use cannot fall between the
/// decision and the park.
pub(crate) fn park_idle() {
    IDLE_PARKED.store(true, core::sync::atomic::Ordering::Release);
}
/// Whether the supervisor is parked.
pub(crate) fn idle_parked() -> bool {
    IDLE_PARKED.load(core::sync::atomic::Ordering::Acquire)
}
/// Resolves after the next [`media_used`] (at once if not parked).
pub(crate) fn media_in_use() -> impl core::future::Future<Output = ()> {
    core::future::poll_fn(|cx| {
        if !idle_parked() {
            return core::task::Poll::Ready(());
        }
        *IDLE_WAKER.lock() = Some(cx.waker().clone());
        if !idle_parked() {
            return core::task::Poll::Ready(());
        }
        core::task::Poll::Pending
    })
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

#[cfg(feature = "kernel-test")]
mod idle_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Linux's amdgpu_vcn_idle_work_handler (and the JPEG one) runs
    /// VCN_IDLE_TIMEOUT (1 s) after a ring's last use and re-queues itself one
    /// timeout later while work remains; a gated engine has no idle work
    /// until it is used again.
    fn navi48_media_idle_runs_on_vcn_idle_timeout() -> TestResult {
        if next_idle_check([Some(0), Some(0)], [false, false], 5_000_000_000).is_some() {
            return TestResult::Fail(
                "the media idle supervisor wakes with both engines gated (every 100 ms)",
            );
        }
        if next_idle_check([Some(0), None], [true, false], 300_000_000) != Some(700_000_000) {
            return TestResult::Fail("idle work does not run VCN_IDLE_TIMEOUT after the last use");
        }
        // VCN busy past its timeout (one timeout later), JPEG used 100 ms ago
        // (900 ms left): the sooner one.
        if next_idle_check([Some(0), Some(1_900_000_000)], [true, true], 2_000_000_000)
            != Some(900_000_000)
        {
            return TestResult::Fail("busy media is re-checked sooner than VCN_IDLE_TIMEOUT");
        }
        if next_idle_check([None, None], [true, true], 0) != Some(1_000_000_000) {
            return TestResult::Fail("unused awake media is not checked a timeout later");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/navi48/media-idle",
        navi48_media_idle_runs_on_vcn_idle_timeout
    );
}
