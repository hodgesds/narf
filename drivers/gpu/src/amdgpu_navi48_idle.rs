//! Generation-bound media idle supervisor. OWNER excludes publication/PM.
use super::*;
static EPOCH: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static GATED: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
pub(super) fn reader(jpeg: bool) -> bool {
    GATED.load(Ordering::Acquire) & (1 << u8::from(jpeg)) != 0
}
pub(super) fn set_reader(jpeg: bool, gated: bool) {
    let bit = 1 << u8::from(jpeg);
    if gated {
        GATED.fetch_or(bit, Ordering::Release);
    } else {
        GATED.fetch_and(!bit, Ordering::Release);
    }
}
pub(super) fn stop() {
    EPOCH.fetch_add(1, Ordering::AcqRel);
}
pub(super) fn start() {
    let epoch = EPOCH.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
    narf_scheduler::spawn(async move {
        loop {
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(100).as_instant()).await;
            if EPOCH.load(Ordering::Acquire) != epoch {
                return;
            }
            let mut owner = OWNER.lock().await;
            if EPOCH.load(Ordering::Acquire) != epoch {
                return;
            }
            let Some(boot) = owner.as_mut() else {
                return;
            };
            if let Err(error) = boot.idle_media(narf_time::monotonic_ns()).await {
                crate::amdgpu_navi48_interrupts::lose();
                if let Some(submitter) = SUBMITTER.lock().clone() {
                    submitter.stop_all();
                }
                use core::fmt::Write;
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: rdna4 media idle failed: {error:?}"
                );
                return;
            }
        }
    });
}
