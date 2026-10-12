//! Boot-only CPU framebuffer handoff for Navi22 GDDR6 training. This is not a
//! runtime pause API: mmap writers cannot be stopped by a software flag.
use core::sync::atomic::{AtomicBool, Ordering};
use narf_drivers_gpu::amdgpu_navi22_platform as platform;
use narf_init::InitResult;

static PAUSED: AtomicBool = AtomicBool::new(false);
static ATTEMPTED: AtomicBool = AtomicBool::new(false);
pub(super) fn paused() -> bool {
    PAUSED.load(Ordering::Acquire)
}

// Taking GLOBAL_FB_CONSOLE drains the only CPU writer already live at boot.
// Other writers are either synchronous sleep pumps (gated above), or tasks
// which have not been polled. No framebuffer view/IRQ guard spans the await.
struct Pause {
    console: Option<narf_graphics::FbConsole>,
}
impl Pause {
    fn new() -> Self {
        PAUSED.store(true, Ordering::Release);
        let console = narf_graphics::console::GLOBAL_FB_CONSOLE.lock().take();
        Self { console }
    }
    fn resume(mut self) {
        *narf_graphics::console::GLOBAL_FB_CONSOLE.lock() = self.console.take();
        PAUSED.store(false, Ordering::Release);
    }
    // Deliberately no automatic resume on Drop. A panic or indeterminate
    // training completion must never expose VRAM to cached writers again.
}

pub(super) fn start() -> InitResult {
    if ATTEMPTED.swap(true, Ordering::AcqRel) {
        return InitResult::NotPresent;
    }
    let framebuffer = *super::BOOT_GENERIC.lock();
    let pause = Pause::new();
    // SAFETY: final synchronous boot initcall, before executor/user startup.
    // No NARF GPU queues/VRAM allocations exist. Console and sleep-pump writes
    // are stopped above, and the original physical GOP geometry is retained.
    let prepared = unsafe { platform::prepare(framebuffer) };
    let affected = match prepared {
        Ok(None) => {
            pause.resume();
            return InitResult::NotPresent;
        }
        Err(error) => {
            // Preparation has issued no device writes and owns no hardware.
            pause.resume();
            use core::fmt::Write;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 preflight refused: {error:?}"
            );
            return InitResult::Error("Navi22 firmware preflight");
        }
        Ok(Some(affected)) => affected,
    };
    // The bridge polls only this self-waking/timer-driven future and sleep
    // pumps, not the executor. No spinlock guard is held; spin works even if
    // this boot profile has not enabled interrupts yet.
    // SAFETY: all CPU writers remain paused until successful terminal return.
    let result = narf_scheduler::block_on_spin(unsafe { platform::run() });
    if result.is_ok() || !affected {
        // A secondary GPU cannot affect the boot framebuffer on another BAR.
        pause.resume();
    }
    use core::fmt::Write;
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: navi22 firmware {:?}; retained {:?}; framebuffer {}",
        result,
        platform::status(),
        if paused() { "quarantined" } else { "available" }
    );
    match result {
        Ok(_) => InitResult::Ok,
        Err(_) => InitResult::Error("Navi22 firmware startup (owner retained)"),
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn navi22_pause_blocks_existing_writers_and_console() -> TestResult {
        let mut pixels = alloc::vec![0u32; 16 * 40];
        let original = narf_graphics::console::GLOBAL_FB_CONSOLE.lock().take();
        // SAFETY: owned test RAM retained throughout installation and pause.
        let fb = unsafe { narf_graphics::Framebuffer::new(pixels.as_mut_ptr(), 16, 40, 16) };
        narf_graphics::install_fb_console(narf_graphics::FbConsole::new(
            fb,
            narf_graphics::Pixel32::WHITE,
            narf_graphics::Pixel32::BLACK,
        ));
        let writer = crate::FbWriter::new(crate::bootstrap_writer()).ok();
        let before = pixels.clone();
        let pause = Pause::new();
        narf_graphics::console::write_bytes(b"X");
        let blocked = writer.as_ref().is_none_or(|w| {
            crate::cursor::drain_and_render(w);
            crate::status::paint(w);
            w.fill(
                crate::Rect {
                    x: 0,
                    y: 0,
                    w: 1,
                    h: 1,
                },
                narf_graphics::Pixel32::WHITE,
            ) == Err(crate::FbWriteError::NoActiveScanout)
        }) && crate::select_active().is_none()
            && crate::fbdev_info().is_none()
            && crate::pump_writer_ref().is_none()
            && pixels == before;
        pause.resume();
        narf_graphics::console::write_bytes(b"X");
        let restored = !paused() && pixels != before;
        let pause = Pause::new();
        drop(pause);
        let quarantined =
            paused() && !narf_graphics::console::is_installed() && crate::select_active().is_none();
        *narf_graphics::console::GLOBAL_FB_CONSOLE.lock() = original;
        PAUSED.store(false, Ordering::Release);
        if !blocked || !restored || !quarantined {
            return TestResult::Fail("Navi22 CPU framebuffer pause/resume");
        }
        TestResult::Pass
    }
    kernel_test_in!("fb", navi22_pause_blocks_existing_writers_and_console);
}
