//! Boot-only CPU framebuffer handoff for discrete AMD GDDR6 training. This is not a
//! runtime pause API: mmap writers cannot be stopped by a software flag.
use core::sync::atomic::{AtomicBool, Ordering};
use narf_drivers_gpu::amdgpu_navi22_platform as platform;
use narf_drivers_gpu::amdgpu_navi48_platform as navi48;
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
    let navi48 = narf_drivers_gpu::amdgpu::with_controller(|g| {
        g.chip.did == narf_drivers_gpu::amdgpu::NAVI48
    })
    .unwrap_or(false);
    let generation = if navi48 { "navi48" } else { "navi22" };
    // The pause exists for one hazard: CPU writers drawing into THIS GPU's
    // VRAM while training/reset owns it. A boot framebuffer provably outside
    // the GPU's VRAM aperture (the iGPU GOP console with the discrete card as
    // a secondary) is not a client of this GPU — the same reasoning that
    // already resumes it after a failed run when `!affected`. Keeping it live
    // is what makes every stage checkpoint visible on screen during the
    // whole cold boot. Unknown geometry or controller data pauses, as before.
    let console_off_gpu = framebuffer_off_gpu(framebuffer);
    let mut pause = (!console_off_gpu).then(Pause::new);
    if console_off_gpu {
        use core::fmt::Write;
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: {generation} boot console is on another device; it stays live"
        );
    }
    let summary_from = narf_console::klog::next_seq();
    // SAFETY: final synchronous boot initcall, before executor/user startup.
    // No NARF GPU queues/VRAM allocations exist. Every CPU writer that could
    // reach this GPU's VRAM is stopped: either the console/pumps are paused
    // above, or the only framebuffer they draw lies outside this GPU's
    // aperture (checked against the probe's VRAM base/size, the same bounds
    // `prepare` classifies `affected` with). The physical GOP geometry is
    // retained.
    let prepared = if navi48 {
        // SAFETY: same final boot handoff and paused writers described above.
        unsafe { navi48::prepare(framebuffer) }.map_err(|e| refused(generation, e))
    } else {
        // SAFETY: same final boot handoff and paused writers described above.
        unsafe { platform::prepare(framebuffer) }.map_err(|e| refused(generation, e))
    };
    let affected = match prepared {
        Ok(None) => {
            resume(pause);
            return InitResult::NotPresent;
        }
        Err(()) => {
            // Preparation has issued no device writes and owns no hardware.
            resume(pause);
            return InitResult::Error("AMD PCIe firmware preflight");
        }
        Ok(Some(affected)) => affected,
    };
    if affected && pause.is_none() {
        // Cannot happen with consistent geometry; never run training with
        // the console drawing into the GPU being trained.
        pause = Some(Pause::new());
    }
    // The bridge polls only this self-waking/timer-driven future and sleep
    // pumps, not the executor. No spinlock guard is held; spin works even if
    // this boot profile has not enabled interrupts yet.
    // SAFETY: all CPU writers remain paused until successful terminal return.
    // `amdgpu.navi22_accel`: advertise native client submission (Mesa
    // radeonsi/RADV). Off by default until validated on hardware.
    narf_drivers_gpu::amdgpu_info_navi22::set_accel(
        narf_boot::args().has_flag("amdgpu.navi22_accel"),
    );
    navi48::set_shader_proof(narf_boot::args().has_flag("amdgpu.shader_proof"));
    navi48::set_media_proof(narf_boot::args().has_flag("amdgpu.media_proof"));
    navi48::set_media_clients(narf_boot::args().has_flag("amdgpu.navi48_media"));
    navi48::set_decode_proof(narf_boot::args().has_flag("amdgpu.decode_proof"));
    navi48::set_encode_proof(narf_boot::args().has_flag("amdgpu.encode_proof"));
    navi48::set_jpeg_proof(narf_boot::args().has_flag("amdgpu.jpeg_proof"));
    navi48::set_jpeg_decode_proof(narf_boot::args().has_flag("amdgpu.jpeg_decode_proof"));
    let ok = if navi48 {
        // SAFETY: the retained prepared owner and paused CPU writers persist.
        let result = narf_scheduler::block_on_spin(unsafe { navi48::run() });
        completed(generation, result, navi48::status());
        result.is_ok()
    } else {
        let args = narf_boot::args();
        platform::set_display_engines(
            args.has_flag("amdgpu.native_display") || args.has_flag("amdgpu.display_probe"),
        );
        // SAFETY: the retained prepared owner and paused CPU writers persist.
        let result = narf_scheduler::block_on_spin(unsafe { platform::run() });
        completed(generation, result, platform::status());
        if result.is_ok() {
            // Polls only the owner lock; the forwarding tasks run later on
            // the executor.
            if let Err(error) = narf_scheduler::block_on_spin(platform::start_fault_service()) {
                use core::fmt::Write;
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: navi22 page faults not reported: {error:?}"
                );
            }
        }
        result.is_ok()
    };
    if ok || !affected {
        // A secondary GPU cannot affect the boot framebuffer on another BAR.
        resume(pause.take());
    }
    use core::fmt::Write;
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: {generation} framebuffer {}",
        if paused() { "quarantined" } else { "available" }
    );
    if ok && !navi48 {
        // Display detection programs the HPD, AUX and DDC engines, so the
        // firmware bring-up stays free of display side effects unless the
        // native display (or an explicit probe) was requested. Both flags
        // are off by default until a board validates the path.
        let native = narf_boot::args().has_flag("amdgpu.native_display");
        if native || narf_boot::args().has_flag("amdgpu.display_probe") {
            report_displays();
        }
        // `amdgpu.navi22_multi`: light every connected sink (KMS CRTCs 1..).
        narf_drivers_gpu::amdgpu_navi22_kms::set_auto_multi(
            narf_boot::args().has_flag("amdgpu.navi22_multi"),
        );
        if native {
            navi22_native_display();
        }
        // Power saving (GFXOFF, clock gating, memory DPM, ...) only on an
        // explicit `amdgpu.navi22_pg=` list; a default boot programs none.
        if let Some(value) = narf_boot::args().value("amdgpu.navi22_pg") {
            // SAFETY: after a successful firmware run; the TDR sampler takes
            // GFXOFF references and no other GC MMIO client runs yet.
            let _ = narf_scheduler::block_on_spin(unsafe { platform::power_saving(value) });
        }
    }
    // `amdgpu.max_bpc=10|12`: allow HDMI deep colour, as DRM's max bpc.
    if let Some(bpc) = narf_boot::args()
        .value("amdgpu.max_bpc")
        .and_then(|v| v.parse::<u8>().ok())
    {
        navi48::set_max_bpc(bpc);
    }
    // `amdgpu.dcfeaturemask`: bit 0x400 (Linux's DC_FRL_MASK)
    // enables HDMI FRL when TMDS cannot carry a mode. Decimal or 0x hex.
    if let Some(mask) = narf_boot::args()
        .value("amdgpu.dcfeaturemask")
        .and_then(
            |v| match v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
                Some(hex) => u32::from_str_radix(hex, 16).ok(),
                None => v.parse::<u32>().ok(),
            },
        )
    {
        navi48::set_frl(mask & 0x400 != 0);
    }
    if ok && navi48 && narf_boot::args().has_flag("amdgpu.native_display") {
        native_display();
    }
    if !navi48 {
        // Last, so it also covers the connector and native-display lines.
        stage_summary(summary_from);
    }
    if ok {
        InitResult::Ok
    } else {
        InitResult::Error("AMD PCIe firmware startup (owner retained)")
    }
}

/// Opt-in (`amdgpu.native_display`) native Navi48 scanout: retire the GOP's
/// DP SST output and light every connected sink natively, the console on
/// the first (DP before HDMI). Off by
/// default until a board has validated the path. On success the published
/// scanout moves the console through the external-scanout observer; on
/// failure the owner stays where it stopped and the boot console remains on
/// the GOP framebuffer, which stays excluded from GPU allocations.
fn native_display() {
    use core::fmt::Write;
    // SAFETY: final synchronous boot initcall, before executor/user startup.
    // Only the boot console writes the GOP framebuffer, whose memory the
    // owner never allocates; retirement stops its scanout role only.
    let retired = narf_scheduler::block_on_spin(unsafe { navi48::retire_inherited_display() });
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: navi48 inherited display {retired:?}"
    );
    if retired.is_err() {
        return;
    }
    // SAFETY: as above; the inherited consumers are now retired.
    let lit =
        narf_scheduler::block_on_spin(unsafe { navi48::modeset_displays(|_, _, row| row.fill(0)) });
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: navi48 native modeset {lit:?}"
    );
    use narf_drivers_gpu::amdgpu_navi48_boot::{Configuration, ModesetError};
    let config = match lit {
        Ok(config) => config,
        // Nothing lightable yet: the monitor lights a sink plugged later.
        Err(ModesetError::NoSink | ModesetError::Link) => Configuration {
            displays: alloc::vec::Vec::new(),
            failed: None,
        },
        Err(_) => return,
    };
    // SAFETY: the retained owner is serialized by the platform; only the
    // monitor and the published hooks drive the displays from here on.
    unsafe { navi48::spawn_display_monitor(config) };
}

fn resume(pause: Option<Pause>) {
    if let Some(pause) = pause {
        pause.resume();
    }
}

/// True only when the boot framebuffer lies entirely outside the probed
/// GPU's CPU-visible VRAM aperture. No framebuffer, no controller data or
/// degenerate geometry all answer `false` (pause, the conservative path).
fn framebuffer_off_gpu(framebuffer: Option<narf_graphics_driver::generic::GenericFb>) -> bool {
    let Some(fb) = framebuffer else {
        return false;
    };
    let Some((base, size)) =
        narf_drivers_gpu::amdgpu::with_controller(|g| (g.vram.base, g.vram.visible_size))
    else {
        return false;
    };
    off_aperture(
        fb.addr,
        u64::from(fb.pitch) * u64::from(fb.height),
        base,
        size,
    )
}

fn off_aperture(addr: u64, bytes: u64, base: u64, size: u64) -> bool {
    let (Some(end), Some(aperture_end)) = (addr.checked_add(bytes), base.checked_add(size)) else {
        return false;
    };
    bytes != 0 && size != 0 && (end <= base || addr >= aperture_end)
}

/// One line per Navi22 cold-boot stage, rebuilt from the checkpoint lines in
/// the log store, then the display/media/thermal notes, so a single photo of
/// the screen (or the tail of the persistent log) shows how far the card got.
/// Printed after the console is back, so it also covers checkpoints drawn
/// while the console was paused.
fn stage_summary(from: u64) {
    use core::fmt::Write;
    let text = narf_console::klog::text_since(from);
    let text = core::str::from_utf8(&text).unwrap_or("");
    let (rows, notes) = summarize_stages(text);
    if rows.is_empty() {
        return;
    }
    let done = rows.iter().filter(|(_, v)| *v == "ok").count();
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: navi22 stage summary ({done}/{} ok):",
        rows.len()
    );
    for (stage, verdict) in rows {
        let _ = writeln!(narf_console::Writer, "  navi22 {stage:<16} {verdict}");
    }
    for note in notes {
        let _ = writeln!(narf_console::Writer, "  navi22 {note}");
    }
}

/// Non-stage boot lines worth repeating in the summary: per-connector
/// detection, native scanout, and media/thermal/queue degradations.
const SUMMARY_NOTES: [&str; 9] = [
    "HDMI-A-",
    "DP-",
    "display",
    "native HDMI",
    "media disabled",
    "thermal",
    "kernel queues disabled",
    "PMFW",
    "EMERGENCY",
];

/// `(stage, verdict)` per stage in first-seen order — `ok`, `failed <error>`,
/// `degraded <error>` / `polling only <error>` (sticky over a later
/// `complete`) or `STARTED (no result)` for a stage that never reported back
/// — plus the [`SUMMARY_NOTES`] lines in log order.
fn summarize_stages(text: &str) -> (alloc::vec::Vec<(&str, &str)>, alloc::vec::Vec<&str>) {
    let mut rows: alloc::vec::Vec<(&str, &str)> = alloc::vec::Vec::new();
    let mut notes = alloc::vec::Vec::new();
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("amdgpu: navi22 ") else {
            continue;
        };
        if SUMMARY_NOTES.iter().any(|p| rest.starts_with(p)) {
            notes.push(rest);
            continue;
        }
        let Some((stage, result)) = rest.split_once(": ") else {
            continue;
        };
        if stage.is_empty() || !stage.bytes().all(|b| b.is_ascii_alphanumeric()) {
            continue;
        }
        let verdict = match result {
            "start" => "STARTED (no result)",
            "complete" => "ok",
            r if r.starts_with("failed")
                || r.starts_with("degraded")
                || r.starts_with("polling only") =>
            {
                r
            }
            _ => continue,
        };
        match rows.iter_mut().find(|(s, _)| *s == stage) {
            Some(row) => {
                let sticky = row.1.starts_with("degraded") || row.1.starts_with("polling only");
                if !(sticky && verdict == "ok") {
                    row.1 = verdict;
                }
            }
            None => rows.push((stage, verdict)),
        }
    }
    (rows, notes)
}

fn refused(generation: &str, error: impl core::fmt::Debug) {
    use core::fmt::Write;
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: {generation} preflight refused: {error:?}"
    );
}
fn completed(generation: &str, result: impl core::fmt::Debug, status: impl core::fmt::Debug) {
    use core::fmt::Write;
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: {generation} firmware {result:?}; retained {status:?}"
    );
}

/// Opt-in native Navi22 HDMI scanout, first drawn as a colour-bar test
/// pattern. On success the published front buffer moves the console (and
/// the fb status panel) there and the amdgpu card gets native KMS state; the
/// display monitor then serves DRM modesets, flips and GPU recovery
/// relights. On failure the retained owner reports where it stopped and the
/// monitor still publishes the connectors. `amdgpu.navi22_hw_cursor` opts in
/// to the DCN3.0 hardware cursor.
fn navi22_native_display() {
    use core::fmt::Write;
    platform::set_hw_cursor(narf_boot::args().has_flag("amdgpu.navi22_hw_cursor"));
    // SAFETY: final synchronous boot initcall after a successful firmware run;
    // no other display client exists and only the console writes scanout.
    let lit = narf_scheduler::block_on_spin(unsafe {
        platform::modeset_displays(narf_drivers_gpu::amdgpu_navi22_modeset::test_pattern)
    });
    let _ = match lit {
        Ok(out) => writeln!(
            narf_console::Writer,
            "amdgpu: navi22 native HDMI {}x{} {} kHz (pm {}, vstartup {}, dispclk {} dppclk {})",
            out.timing.h_active,
            out.timing.v_active,
            out.timing.pixel_clock_khz,
            out.prefetch_mode,
            out.v_startup,
            out.dispclk_khz,
            out.dppclk_khz
        ),
        Err(error) => writeln!(
            narf_console::Writer,
            "amdgpu: navi22 native HDMI failed {error:?}; state {:?}",
            platform::modeset_state()
        ),
    };
    // SAFETY: from here on only the monitor and the published hooks drive
    // the display; the owner lock serializes them.
    unsafe { platform::spawn_display_monitor() };
}

/// One serial line per board connector from native AUX/DDC/HPD detection, so
/// the first bare-metal boot shows which sinks and EDIDs were seen. This
/// enables and programs the HPD, AUX and DDC engines (register writes) but
/// changes no stream, scanout or framebuffer state.
fn report_displays() {
    use core::fmt::Write;
    use narf_drivers_gpu::amdgpu_navi22_display::{Detection, Signal};
    let reports = match narf_scheduler::block_on_spin(platform::detect_displays()) {
        Ok(reports) => reports,
        Err(error) => {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 display probe: {error:?}"
            );
            return;
        }
    };
    for report in reports {
        let c = report.connector;
        let name = match c.signal {
            Signal::Hdmi => "HDMI-A",
            Signal::DisplayPort => "DP",
        };
        let _ = write!(
            narf_console::Writer,
            "amdgpu: navi22 {name}-{} (ddc {}, hpd {:?}, dig {}): ",
            c.path.connector_instance,
            c.line,
            c.hpd,
            c.path.transmitter
        );
        let _ = match report.detection {
            Detection::Disconnected => writeln!(narf_console::Writer, "disconnected"),
            Detection::Failed(error) => writeln!(narf_console::Writer, "sink error {error:?}"),
            Detection::Connected(sink) => match sink.preferred {
                Some(t) => writeln!(
                    narf_console::Writer,
                    "EDID {} bytes, preferred {}x{} {} kHz{}",
                    sink.edid.len(),
                    t.h_active,
                    t.v_active,
                    t.pixel_clock_khz,
                    if sink.hdmi { ", HDMI" } else { "" }
                ),
                None => writeln!(
                    narf_console::Writer,
                    "EDID {} bytes, no preferred timing",
                    sink.edid.len()
                ),
            },
        };
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

    /// The console stays live only for a framebuffer wholly outside the
    /// GPU's aperture; overlap, touching-inside and degenerate inputs pause.
    fn navi22_console_off_gpu_classification() -> TestResult {
        const BASE: u64 = 0x80_0000_0000;
        const SIZE: u64 = 16 << 30;
        let fb = 1920 * 4 * 1080;
        let cases = [
            // iGPU GOP below and above the discrete aperture.
            (0xD000_0000, fb, true),
            (BASE + SIZE, fb, true),
            (BASE - fb, fb, true),
            // On the card, straddling either edge.
            (BASE, fb, false),
            (BASE + SIZE - fb, fb, false),
            (BASE - 4096, fb, false),
            (BASE + SIZE - 4096, fb, false),
            // Degenerate geometry / overflow.
            (0xD000_0000, 0, false),
            (u64::MAX - 10, fb, false),
        ];
        for (addr, bytes, off) in cases {
            if off_aperture(addr, bytes, BASE, SIZE) != off {
                return TestResult::Fail("framebuffer/aperture classification");
            }
        }
        if off_aperture(0xD000_0000, fb, BASE, 0) || framebuffer_off_gpu(None) {
            return TestResult::Fail("unknown aperture or framebuffer must pause");
        }
        TestResult::Pass
    }
    kernel_test_in!("fb", navi22_console_off_gpu_classification);

    fn navi22_stage_summary_rows() -> TestResult {
        let log = "\
amdgpu: navi22 ResetOnInit: start
amdgpu: navi22 ResetOnInit: complete
amdgpu: navi22 boot console is on another device; it stays live
amdgpu: navi22 MemoryTraining: start
amdgpu: navi22 MemoryTraining: complete
amdgpu: navi22 kernel queues disabled: doorbells Unmapped
amdgpu: navi22 Sos: start
amdgpu: navi22 Sos: failed Psp(Timeout)
amdgpu: navi22 page faults not reported: Invalid
amdgpu: navi22 Ring: start
amdgpu: navi22 FenceInterrupts: start
amdgpu: navi22 FenceInterrupts: polling only Timeout
amdgpu: navi22 FenceInterrupts: complete
amdgpu: navi22 VcnStart: start
amdgpu: navi22 VcnStart: degraded Ring
amdgpu: navi22 HDMI-A-1 (ddc 1, hpd Some(0), dig 0): disconnected
amdgpu: navi22 thermal alert Ctf
";
        let (rows, notes) = summarize_stages(log);
        let want = [
            ("ResetOnInit", "ok"),
            ("MemoryTraining", "ok"),
            ("Sos", "failed Psp(Timeout)"),
            ("Ring", "STARTED (no result)"),
            ("FenceInterrupts", "polling only Timeout"),
            ("VcnStart", "degraded Ring"),
        ];
        let want_notes = [
            "kernel queues disabled: doorbells Unmapped",
            "HDMI-A-1 (ddc 1, hpd Some(0), dig 0): disconnected",
            "thermal alert Ctf",
        ];
        if rows.as_slice() != want.as_slice() || notes.as_slice() != want_notes.as_slice() {
            return TestResult::Fail("stage summary rows");
        }
        TestResult::Pass
    }
    kernel_test_in!("fb", navi22_stage_summary_rows);
}
