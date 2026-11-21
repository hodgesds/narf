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
    // A parked supervisor sees the new epoch and exits.
    crate::amdgpu_navi48_media_power::media_used();
}
pub(super) fn start() {
    let epoch = EPOCH.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
    crate::amdgpu_navi48_media_power::media_used();
    narf_scheduler::spawn(async move {
        // Linux's idle work runs VCN_IDLE_TIMEOUT after a use.
        let mut delay = 1_000_000_000; // linux: VCN_IDLE_TIMEOUT
        loop {
            // Every engine gated or absent: nothing until the next use.
            if crate::amdgpu_navi48_media_power::idle_parked() {
                crate::amdgpu_navi48_media_power::media_in_use().await;
                delay = 1_000_000_000; // linux: VCN_IDLE_TIMEOUT
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_ns(delay).as_instant()).await;
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
            match boot.media_idle_recheck(narf_time::monotonic_ns()) {
                Some(ns) => delay = ns,
                // Under OWNER, which `begin_media_use` also holds.
                None => crate::amdgpu_navi48_media_power::park_idle(),
            }
        }
    });
}
