//! Boot handoff for the DCN314 display owner. Firmware reservations come from
//! ATOM; live scanouts and cursors are inventoried before allocating VRAM.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_dcn_display::{timing_from_edid, Pipeline, Scanout},
    amdgpu_dcn_stream::Depth,
    amdgpu_dml::Format,
    amdgpu_dmub::Firmware,
    amdgpu_dmub_boot::{Error, Loader},
    amdgpu_vram::Pool,
};
use alloc::{sync::Arc, vec::Vec};
use core::ops::Range;
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, CapError, CapOp, Read, Write};
use narf_lib::sync::IrqSafeSpinLock;

static BOOT_FB: IrqSafeSpinLock<Option<narf_graphics_driver::generic::GenericFb>> =
    IrqSafeSpinLock::new(None);
/// Record the physical boot framebuffer before fbdev replaces its address with
/// a virtual mapping. Recording geometry performs no GPU access or allocation.
pub fn record_boot_framebuffer(fb: narf_graphics_driver::generic::GenericFb) {
    let mut saved = BOOT_FB.lock();
    if saved.is_none() {
        *saved = Some(fb);
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
struct CopyToc;
impl CapOp<narf_firmware::FirmwareBlob, Read> for CopyToc {
    type Output = Result<Vec<u8>, Error>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareBlob, Read>,
    ) -> Result<Self::Output, CapError> {
        Ok((|| {
            let view = narf_firmware::view_of(cap).map_err(|_| Error::Invalid)?;
            crate::amdgpu_psp_ring::toc_payload(view.bytes).map_err(Error::Psp)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(view.bytes.len())
                .map_err(|_| Error::Allocation)?;
            bytes.extend_from_slice(view.bytes);
            Ok(bytes)
        })())
    }
}
struct OpenToc;
impl CapOp<narf_firmware::FirmwareRegistry, Read> for OpenToc {
    type Output = Result<Vec<u8>, Error>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self::Output, CapError> {
        let blob = match narf_firmware::open("amdgpu/psp_13_0_4_toc.bin", cap) {
            Ok(blob) => blob,
            Err(_) => return Ok(Err(Error::Invalid)),
        };
        blob.invoke(CopyToc)
    }
}

// ── The boot-inventory register windows ───────────────────────────────────
//
// `amdgpu_psp_ring::bank`'s fourth argument indexes `ip.base_addrs`, so it is
// the register's SOC15 `_BASE_IDX` — a property of the REGISTER, not of the IP
// block or of its instance. The fifth is the highest dword this file reads
// through that base, which `bank` bounds-checks against the BAR.
//
// DCN: every HUBP / HUBPREQ / CURSOR register read below is `_BASE_IDX 2` in
// `dcn/dcn_3_1_4_offset.h`.
const DCN_BASE_IDX: usize = 2;
/// `regCURSOR0_3_CURSOR_SIZE` = 0x090f — highest dword `scan_surfaces` reads
/// (`regCURSOR0_0_CURSOR_SIZE` 0x067b + 3 × `HUBP_PIPE_STRIDE`).
const CURSOR0_3_CURSOR_SIZE: u32 = 0x090f;
/// `regHUBP3_DCHUBP_CNTL` = 0x0887 — highest hub dword `free_pipe` reads.
const HUBP3_DCHUBP_CNTL: u32 = 0x0887;
/// `regOTG3_OTG_CONTROL` = 0x1cc1 — highest timing-generator dword `free_pipe`
/// reads.
const OTG3_OTG_CONTROL: u32 = 0x1cc1;

// GC: `gc/gc_11_0_0_offset.h` serves every GC 11.0.x — `gfx_v11_0.c` includes
// it unconditionally — and puts `regGCVM_CONTEXT0_CNTL` at 0x1688 on
// `_BASE_IDX 0`.
const GC_BASE_IDX: usize = 0;
const GCVM_CONTEXT0_CNTL: u32 = 0x1688;

// MMHUB: Phoenix is MMHUB 3.0.1. Linux `gmc_v11_0.c:578` selects
// `mmhub_v3_0_1_funcs` for that version, and `mmhub_v3_0_1.c:27` includes
// `mmhub/mmhub_3_0_1_offset.h`, where `regMMVM_CONTEXT0_CNTL` is 0x0740 with
// `_BASE_IDX` **1**.
//
// The three MMHUB 3.0.x headers share no window, so no single (base index,
// offset) pair can serve all three: 3.0.0 puts the same 0x0740 on
// `_BASE_IDX 0`, while 3.0.2 moves the register to 0x06c0. This accepted all
// three against `_BASE_IDX 0` + 0x0740 — the wrong segment on the hardware we
// target and the wrong register on 3.0.2 — so the sixteen reads landed
// somewhere unrelated and the handoff either refused a quiescent GPU or
// admitted a live VM context, on whatever bit 0 those dwords happened to
// carry. `amdgpu_vmhub_regs` already records that this generation's MMHUB is
// BASE_IDX 1; only the version whose window this is gets accepted here.
const MMHUB_VERSIONS: &[(u8, u8, u8)] = &[(3, 0, 1)];
const MMHUB_BASE_IDX: usize = 1;
const MMVM_CONTEXT0_CNTL: u32 = 0x0740;

/// Both hubs carry sixteen VM contexts one dword apart
/// (`regGCVM_CONTEXT1_CNTL` 0x1689, `regMMVM_CONTEXT1_CNTL` 0x0741), each with
/// `ENABLE_CONTEXT` in bit 0.
const VM_CONTEXTS: u32 = 16;
const VM_CONTEXT_ENABLE: u32 = 1 << 0;

/// Production boot has not initialized GFX/GART or other driver VRAM clients.
/// Reject live VM contexts rather than guessing the size of inherited tables.
fn inventory(gpu: &AmdGpu, cap: &Cap<BusDeviceCap, Write>) -> Result<Vec<Range<u64>>, Error> {
    use crate::amdgpu_discovery as ip;
    let dcn = crate::amdgpu_psp_ring::bank(
        gpu,
        ip::HW_ID_DCN,
        &[(3, 1, 4)],
        DCN_BASE_IDX,
        CURSOR0_3_CURSOR_SIZE,
    )
    .map_err(Error::Psp)?;
    let gc = crate::amdgpu_psp_ring::bank(
        gpu,
        ip::HW_ID_GC,
        &[(11, 0, 1), (11, 0, 4)],
        GC_BASE_IDX,
        GCVM_CONTEXT0_CNTL + VM_CONTEXTS - 1,
    )
    .map_err(Error::Psp)?;
    let hub = crate::amdgpu_psp_ring::bank(
        gpu,
        ip::HW_ID_MMHUB,
        MMHUB_VERSIONS,
        MMHUB_BASE_IDX,
        MMVM_CONTEXT0_CNTL + VM_CONTEXTS - 1,
    )
    .map_err(Error::Psp)?;
    if gpu.fw_loaded || gpu.mode.is_some() {
        return Err(Error::Busy);
    }
    cap.invoke(Op(|| {
        for (base, first) in [(gc, GCVM_CONTEXT0_CNTL), (hub, MMVM_CONTEXT0_CNTL)] {
            for index in 0..u64::from(VM_CONTEXTS) {
                // SAFETY: exact IP bank and entire context array bounded above.
                let value = unsafe { gpu.regs.read32(base + (u64::from(first) + index) * 4) };
                if value == u32::MAX || value & VM_CONTEXT_ENABLE != 0 {
                    return Err(Error::Busy);
                }
            }
        }
        // SAFETY: bank validation bounds all four HUBP/cursor instances.
        scan_surfaces(|reg| unsafe { gpu.regs.read32(dcn + reg as u64 * 4) })
    }))
    .map_err(|_| Error::Revoked)?
}
// The inherited-scanout window. Every id below is `_BASE_IDX 2` in
// `dcn/dcn_3_1_4_offset.h`, and every mask is the one `dcn_3_1_4_sh_mask.h`
// gives for the named field:
//
//   regHUBP0_DCSURF_SURFACE_CONFIG            0x05e5  SURFACE_PIXEL_FORMAT 0x7f
//   regHUBP0_DCSURF_TILING_CONFIG             0x05e7  SW_MODE              0x1f
//   regHUBP0_DCSURF_PRI_VIEWPORT_START        0x05e9  X/Y_START          0x3fff
//   regHUBP0_DCSURF_PRI_VIEWPORT_DIMENSION    0x05ea  WIDTH/HEIGHT       0x3fff
//   regHUBP0_DCHUBP_CNTL                      0x05f3  HUBP_BLANK_EN         0x1
//   regHUBPREQ0_DCSURF_SURFACE_PITCH          0x0607  PITCH              0x3fff
//   regHUBPREQ0_VMID_SETTINGS_0               0x0609  VMID                  0xf
//   regHUBPREQ0_DCSURF_PRIMARY_SURFACE_ADDRESS        0x060a  (+1 = _HIGH)
//   regHUBPREQ0_DCSURF_SECONDARY_SURFACE_ADDRESS      0x060e  (+1 = _HIGH)
//   regHUBPREQ0_DCSURF_SURFACE_CONTROL        0x061a
//   regHUBPREQ0_DCSURF_SURFACE_INUSE          0x0621  (+1 = _HIGH)
//   regHUBPREQ0_DCSURF_SURFACE_EARLIEST_INUSE 0x0625  (+1 = _HIGH)
//   regCURSOR0_0_CURSOR_CONTROL               0x0678
//   regCURSOR0_0_CURSOR_SURFACE_ADDRESS       0x0679  (+1 = _HIGH)
//   regCURSOR0_0_CURSOR_SIZE                  0x067b  HEIGHT/WIDTH       0x1ff
//
// `_ADDRESS_HIGH` is 0x0000ffff wide on both the surface and the cursor, so a
// high half with anything above bit 15 set is not an address this GPU wrote.
const SURFACE_CONFIG: u32 = 0x05e5;
const TILING_CONFIG: u32 = 0x05e7;
const PRI_VIEWPORT_START: u32 = 0x05e9;
const PRI_VIEWPORT_DIMENSION: u32 = 0x05ea;
const VMID_SETTINGS_0: u32 = 0x0609;
const SURFACE_CONTROL: u32 = 0x061a;
const SURFACE_INUSE: u32 = 0x0621;
const SURFACE_EARLIEST_INUSE: u32 = 0x0625;
const SECONDARY_SURFACE_ADDRESS: u32 = 0x060e;
const CURSOR_CONTROL: u32 = 0x0678;
const CURSOR_SURFACE_ADDRESS: u32 = 0x0679;
const CURSOR_SIZE: u32 = 0x067b;

const SURFACE_PIXEL_FORMAT: u32 = 0x7f;
const SW_MODE: u32 = 0x1f;
/// `PRIMARY_SURFACE_TMZ` | `PRIMARY_SURFACE_DCC_EN` |
/// `SECONDARY_SURFACE_TMZ` | `SECONDARY_SURFACE_DCC_EN`. With DCC off there is
/// no metadata surface to account for.
const SURFACE_PROTECTED_OR_COMPRESSED: u32 = 0x0303;
const VMID: u32 = 0xf;
const VIEWPORT_COORD: u32 = 0x3fff;
const PITCH: u32 = 0x3fff;
const ADDRESS_HIGH: u32 = 0xffff;
const CURSOR_ENABLE: u32 = 1 << 0;
/// `CURSOR_MODE` is 0x00000700 — three bits at 8.
const CURSOR_MODE: u32 = 0x7;
const CURSOR_MODE_SHIFT: u32 = 8;
const CURSOR_TMZ: u32 = 1 << 12;
/// `CURSOR_PITCH` is 0x00030000 — two bits at 16, encoding 64 << n.
const CURSOR_PITCH: u32 = 0x3;
const CURSOR_PITCH_SHIFT: u32 = 16;
const CURSOR_DIM: u32 = 0x1ff;

fn scan_surfaces(mut read: impl FnMut(u32) -> u32) -> Result<Vec<Range<u64>>, Error> {
    let mut ranges = Vec::new();
    let mut read = |reg| {
        let v = read(reg);
        if v == u32::MAX {
            Err(Error::Invalid)
        } else {
            Ok(v)
        }
    };
    for index in 0..u32::from(crate::amdgpu_dcn::DCN_PIPES) {
        let delta = index * crate::amdgpu_dcn::HUBP_PIPE_STRIDE;
        if read(crate::amdgpu_dcn::HUBP0_DCHUBP_CNTL + delta)? & crate::amdgpu_dcn::HUBP_BLANK_FORCE
            == 0
        {
            // Only packed, linear RGB is a bounded inherited scanout here.
            // Reject DCC/YUV/stereo/VM surfaces instead of overlooking metadata.
            //
            // `hubp1_program_pixel_format` in Linux
            // `display/dc/hubp/dcn10/dcn10_hubp.c` is the encoding: 1 ARGB1555
            // and 3 RGB565 are two bytes, 8 A*GB8888 and 10 A*GB2101010 four,
            // 24 ARGB16161616F and 26 ARGB16161616_UNORM eight. 12
            // (AYCrCb8888), 65..=67 (420 YCbCr/YCrCb) and 112..=119 are the
            // YUV and packed-float formats this handoff will not size.
            let format = read(SURFACE_CONFIG + delta)? & SURFACE_PIXEL_FORMAT;
            let bpp = match format {
                1 | 3 => 2,
                8 | 10 => 4,
                24 | 26 => 8,
                _ => return Err(Error::Unsupported),
            };
            if read(TILING_CONFIG + delta)? & SW_MODE != 0
                || read(SURFACE_CONTROL + delta)? & SURFACE_PROTECTED_OR_COMPRESSED != 0
                || read(VMID_SETTINGS_0 + delta)? & VMID != 0
            {
                return Err(Error::Unsupported);
            }
            let viewport = read(PRI_VIEWPORT_DIMENSION + delta)?;
            let start = read(PRI_VIEWPORT_START + delta)?;
            let pitch =
                (read(crate::amdgpu_dcn::HUBPREQ0_DCSURF_SURFACE_PITCH + delta)? & PITCH) + 1;
            let rows = ((start >> 16) & VIEWPORT_COORD) + ((viewport >> 16) & VIEWPORT_COORD);
            if rows == 0
                || (viewport & VIEWPORT_COORD) == 0
                || (start & VIEWPORT_COORD) + (viewport & VIEWPORT_COORD) > pitch
            {
                return Err(Error::Invalid);
            }
            let size = pitch as u64 * rows as u64 * bpp;
            // Include the programmed primary and secondary surfaces and both
            // in-use reports: a boot-time flip can still be draining its
            // previous allocation. The secondary surface is the stereo right
            // eye, which shares the primary's pitch and so its size.
            let before = ranges.len();
            for reg in [
                crate::amdgpu_dcn::HUBPREQ0_DCSURF_PRIMARY_SURFACE_ADDRESS,
                SECONDARY_SURFACE_ADDRESS,
                SURFACE_INUSE,
                SURFACE_EARLIEST_INUSE,
            ] {
                let low = read(reg + delta)?;
                let high = read(reg + 1 + delta)?;
                if high & !ADDRESS_HIGH != 0 {
                    return Err(Error::Invalid);
                }
                let address = low as u64 | (high as u64) << 32;
                if address != 0 {
                    ranges.push(address..address.checked_add(size).ok_or(Error::Invalid)?);
                }
            }
            if ranges.len() == before {
                return Err(Error::Invalid);
            }
        }
        let control = read(CURSOR_CONTROL + delta)?;
        if control & CURSOR_ENABLE != 0 {
            // `CURSOR_MODE` 1..=3 are the 32-bit-per-pixel formats
            // (`COLOR_1BIT_AND`, `COLOR_PRE_MULTIPLIED_ALPHA`,
            // `COLOR_UN_PRE_MULTIPLIED_ALPHA` in Linux `dc/dc_hw_types.h`);
            // 0 is mono and 4..=5 are the 64-bit float ones, none of which the
            // four-bytes-per-pixel size below would describe.
            let mode = (control >> CURSOR_MODE_SHIFT) & CURSOR_MODE;
            if !matches!(mode, 1..=3) || control & CURSOR_TMZ != 0 {
                return Err(Error::Unsupported);
            }
            let size = read(CURSOR_SIZE + delta)?;
            let rows = size & CURSOR_DIM;
            let width = (size >> 16) & CURSOR_DIM;
            let pitch = 64u64 << ((control >> CURSOR_PITCH_SHIFT) & CURSOR_PITCH);
            if rows == 0 || width == 0 || width as u64 > pitch || pitch > 256 {
                return Err(Error::Invalid);
            }
            let address = read(CURSOR_SURFACE_ADDRESS + delta)? as u64
                | (read(CURSOR_SURFACE_ADDRESS + 1 + delta)? as u64) << 32;
            ranges.push(
                address
                    ..address
                        .checked_add(pitch * rows as u64 * 4)
                        .ok_or(Error::Invalid)?,
            );
        }
    }
    Ok(ranges)
}

/// Build the one platform display owner without issuing hardware writes.
/// Failure here permits retaining the pre-existing firmware attachment.
/// Report a failed boot-handoff stage on the console.
///
/// `prepare` has eleven distinct early returns and `start` used to collapse
/// every one of them into a bare `return false`, so a machine that got no
/// native display looked identical whether the firmware blob was missing, the
/// VBIOS was unreadable, VRAM could not be claimed or the PSP ring never came
/// up. Several of those are a one-line fix once you know which one it is.
///
/// Two variants are reachable from more than one place, so the stage name
/// carries the information the variant cannot: `Invalid` from the boot
/// framebuffer record and from its geometry arithmetic, `Revoked` from PCI
/// authority, the firmware registry and the TOC.
fn stage_failed<T>(stage: &str, result: Result<T, Error>) -> Result<T, Error> {
    if let Err(error) = &result {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: boot handoff refused at {stage}: {error:?}"
        );
    }
    result
}

pub(crate) fn prepare() -> Result<(Loader, Arc<Pool>), Error> {
    let boot = stage_failed(
        "boot-framebuffer-record",
        BOOT_FB.lock().ok_or(Error::Invalid),
    )?;
    let size = (boot.pitch as u64)
        .checked_mul(boot.height as u64)
        .filter(|n| *n != 0)
        .ok_or(Error::Invalid)?;
    let boot_range = stage_failed(
        "boot-framebuffer-geometry",
        boot.addr
            .checked_add(size)
            .map(|end| boot.addr..end)
            .ok_or(Error::Invalid),
    )?;
    let cap = stage_failed(
        "pci-authority",
        crate::amdgpu::pci_authority().ok_or(Error::Revoked),
    )?;
    let fw_cap: Cap<narf_firmware::FirmwareRegistry, Read> = stage_failed(
        "firmware-registry",
        narf_firmware::trusted_loader_authority()
            .ok_or(Error::Revoked)
            .and_then(|a| a.derive().map_err(|_| Error::Revoked)),
    )?;
    let toc = stage_failed(
        "psp-toc-open",
        fw_cap.invoke(OpenToc).map_err(|_| Error::Revoked)?,
    )?;
    crate::amdgpu::with_controller(|gpu| {
        let firmware = stage_failed(
            "firmware-open",
            Firmware::open(gpu, &fw_cap).map_err(Error::Firmware),
        )?;
        let clients = stage_failed("display-inventory", inventory(gpu, &cap))?;
        // SAFETY: sole boot owner, no NARF clients have initialized; VM clients
        // are rejected and all live supported scanouts/cursors inventoried.
        let plan = unsafe { crate::amdgpu_vram_boot::Plan::read(gpu, &cap, boot_range, &clients) }
            .map_err(Error::Memory);
        let plan = stage_failed("vram-boot-plan", plan)?;
        // SAFETY: boot handoff owns the free VRAM; all subsequent display
        // clients share this pool. Firmware and boot surfaces remain excluded.
        let pool = Arc::new(stage_failed(
            "vram-pool",
            unsafe { plan.into_pool() }.map_err(Error::Memory),
        )?);
        // SAFETY: exact GPU, authenticated containers, lifetime mappings and
        // exclusive PSP/DMUB ownership are retained by the loader and pool.
        let loader = stage_failed("psp-loader", unsafe {
            Loader::new_psp(gpu, cap, &pool, &firmware, &toc)
        })?;
        Ok((loader, pool))
    })
    .ok_or(Error::Unsupported)
    .inspect_err(|_| {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: boot handoff refused: no AMD controller bound"
        );
    })?
}

/// A hub pixel pipe is free when it is blanked and its timing generator is
/// stopped; claiming one that is not would disturb a live scanout. These are the
/// same two signals the boot inventory uses to decide a surface is in use.
fn idle_pipe(mut state: impl FnMut(u8) -> (u32, u32)) -> Option<u8> {
    for pipe in 0..4u8 {
        let (blank, master) = state(pipe);
        // An all-ones read is a vanished device, not an idle pipe.
        if blank == u32::MAX || master == u32::MAX {
            return None;
        }
        if blank & crate::amdgpu_dcn::HUBP_BLANK_FORCE != 0
            && master & crate::amdgpu_dcn::OTG_MASTER_EN == 0
        {
            return Some(pipe);
        }
    }
    None
}
fn free_pipe(gpu: &AmdGpu, cap: &Cap<BusDeviceCap, Write>) -> Option<u8> {
    use crate::amdgpu_discovery as ip;
    let hubp = crate::amdgpu_psp_ring::bank(
        gpu,
        ip::HW_ID_DCN,
        &[(3, 1, 4)],
        DCN_BASE_IDX,
        HUBP3_DCHUBP_CNTL,
    )
    .ok()?;
    let otg = crate::amdgpu_psp_ring::bank(
        gpu,
        ip::HW_ID_DCN,
        &[(3, 1, 4)],
        DCN_BASE_IDX,
        OTG3_OTG_CONTROL,
    )
    .ok()?;
    cap.invoke(Op(|| {
        idle_pipe(|pipe| {
            use crate::amdgpu_dcn as dcn;
            let hub_reg = dcn::for_pipe(dcn::HUBP0_DCHUBP_CNTL, pipe, dcn::HUBP_PIPE_STRIDE);
            let otg_reg = dcn::for_pipe(dcn::OTG0_OTG_CONTROL, pipe, dcn::OTG_PIPE_STRIDE);
            // SAFETY: both banks are bounded above for all four instances.
            unsafe {
                (
                    gpu.regs.read32(hubp + u64::from(hub_reg) * 4),
                    gpu.regs.read32(otg + u64::from(otg_reg) * 4),
                )
            }
        })
    }))
    .ok()
    .flatten()
}

/// Bring up the first sink the board can answer for. Attempted once per boot:
/// the clock manager publishes a table buffer to firmware, so a retried failure
/// would quarantine another reservation each time, and re-running a sequence
/// that has already failed once is unlikely to do better.
async fn arm(display: &mut Display, sinks: &[crate::amdgpu_usbc::Sink]) {
    use core::fmt::Write as _;
    if display.attempted || display.stream.is_some() {
        return;
    }
    let Some(cap) = crate::amdgpu::pci_authority() else {
        return;
    };
    for sink in sinks {
        // A mode the sink does not declare, or one this pipeline cannot drive,
        // is not a reason to mark the attempt spent.
        let Ok(block) = narf_edid::Block::parse(&sink.edid) else {
            continue;
        };
        let Some(detailed) = block.preferred_mode() else {
            continue;
        };
        let Ok(timing) = timing_from_edid(&detailed) else {
            continue;
        };
        let pool = display.pool.clone();
        let Some(Some((mut pipeline, pipe))) = crate::amdgpu::with_controller(|gpu| {
            let pipe = free_pipe(gpu, &cap)?;
            // SAFETY: the pipe is idle, the pool is this driver's, and the route
            // is derived from the retained VBIOS snapshot for this device.
            let pipeline = unsafe {
                Pipeline::for_sink(gpu, cap, &pool, pipe, gpu.vbios.as_ref()?.bytes(), sink)
            }
            .ok()?;
            Some((pipeline, pipe))
        }) else {
            continue;
        };
        display.attempted = true;
        let Ok(mut scanout) = Scanout::reserve(&pool, &timing, Format::Rgb32) else {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu-usbc: no VRAM for a {}x{} scanout",
                timing.h_active,
                timing.v_active
            );
            return;
        };
        // Black, not whatever this VRAM held, before any pixel is sent.
        scanout.clear().await;
        let mut platform = None;
        let brought_up = async {
            pipeline.start().await?;
            let constants = crate::amdgpu::with_controller(|gpu| {
                // SAFETY: live PCI authority and the retained VBIOS snapshot.
                unsafe {
                    pipeline
                        .platform(gpu, &cap, gpu.vbios.as_ref()?.bytes())
                        .ok()
                }
            })
            .flatten()
            .ok_or(crate::amdgpu_dcn_display::Error::Unsupported)?;
            platform = Some(constants);
            pipeline
                .enable(
                    &mut display.loader,
                    &scanout,
                    &timing,
                    &constants,
                    Depth::Bpc8,
                    sink.dpcd,
                )
                .await
        }
        .await;
        let Some(platform) = platform else {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu-usbc: external modeset failed, display left alone: {brought_up:?}"
            );
            return;
        };
        match brought_up {
            Ok(()) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu-usbc: external {}x{} stream on pipe {pipe}",
                    timing.h_active,
                    timing.v_active
                );
                display.stream = Some(Stream {
                    pipeline,
                    scanout,
                    timing,
                    platform,
                    depth: Depth::Bpc8,
                    caps: sink.dpcd,
                });
            }
            Err(error) => {
                // enable() already tore the stream back down, so the existing
                // attach-only behaviour is what remains.
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu-usbc: external modeset failed, display left alone: {error:?}"
                );
            }
        }
        return;
    }
}

/// A running external stream, with everything needed to put it back after a
/// suspend. The mode, platform constants and sink capabilities are retained
/// rather than re-derived, so a replay cannot land on a different mode than the
/// one that was validated.
struct Stream {
    pipeline: Pipeline,
    /// The scanout outlives the pipe that fetches from it.
    scanout: Scanout,
    timing: crate::amdgpu_dml::Timing,
    platform: crate::amdgpu_dcn_display::Platform,
    depth: Depth,
    caps: [u8; 16],
}
struct Display {
    loader: Loader,
    // Every future scanout allocation must share this pool.
    pool: Arc<Pool>,
    stream: Option<Stream>,
    attempted: bool,
}
static DISPLAY: narf_lib::mutex::Mutex<Option<Display>> = narf_lib::mutex::Mutex::new(None);

pub(crate) fn start() -> bool {
    // Every `false` below means "the native path did not take"; the caller
    // then falls back to attaching to running DAL firmware, which leaves the
    // panel on the UEFI framebuffer. That fallback used to be silent and
    // indistinguishable from success on a machine whose boot framebuffer
    // already shows the right thing.
    let (loader, pool) = match prepare() {
        Ok(prepared) => prepared,
        // `prepare` has already named the stage.
        Err(_) => return false,
    };
    let Some(mut owner) = DISPLAY.try_lock() else {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: display owner lock held; native bring-up skipped"
        );
        return false;
    };
    if owner.is_some() {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: display owner already claimed; native bring-up skipped"
        );
        return false;
    }
    *owner = Some(Display {
        loader,
        pool,
        stream: None,
        attempted: false,
    });
    drop(owner);
    crate::amdgpu_usbc::observe_connectors();
    narf_scheduler::spawn(async {
        {
            let mut guard = DISPLAY.lock().await;
            let display = guard.as_mut().unwrap();
            let result = async {
                display.loader.boot(Default::default()).await?;
                display.loader.enable_notifications().await
            }
            .await;
            if let Err(error) = result {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu-usbc: PSP/DMUB boot failed: {error:?}"
                );
                // Retain both the owner and busy phase after a partial boot.
                // No attach fallback can race an outstanding PSP command.
                return;
            }
        }
        crate::amdgpu_usbc::finish_cycle();
        loop {
            if crate::amdgpu_usbc::begin_cycle() {
                let result = {
                    let mut guard = DISPLAY.lock().await;
                    guard.as_mut().unwrap().loader.discover_sinks().await
                };
                match result {
                    Ok(found) => {
                        {
                            let mut guard = DISPLAY.lock().await;
                            arm(guard.as_mut().unwrap(), &found).await;
                        }
                        crate::amdgpu_usbc::publish_sinks(found);
                    }
                    Err(error) => {
                        use core::fmt::Write as _;
                        crate::amdgpu_usbc::publish_sinks(Vec::new());
                        let _ = writeln!(
                            narf_console::Writer,
                            "amdgpu-usbc: owned DMUB discovery failed: {error:?}"
                        );
                        return;
                    }
                }
                crate::amdgpu_usbc::finish_cycle();
            }
            crate::amdgpu_usbc::wait_for_rescan().await;
        }
    });
    true
}

/// Synchronous PM bridge. No IRQ-safe lock is held and the polled hardware
/// futures depend only on device completion/time, never another executor task.
pub(crate) fn suspend() -> bool {
    let Some(mut guard) = DISPLAY.try_lock() else {
        return false;
    };
    let Some(display) = guard.as_mut() else {
        return true;
    };
    if narf_scheduler::current_task_id().raw() != 0 {
        return false;
    }
    let Display { loader, stream, .. } = display;
    // Stop the stream before the firmware: a pipe left fetching across a GPU
    // suspend would read scanout memory the resume path has not re-established.
    // The stream itself is kept, with the mode it was validated for, so resume
    // puts back the same one rather than re-deriving a possibly different mode.
    if let Some(stream) = stream.as_mut() {
        if narf_scheduler::block_on_spin(stream.pipeline.disable(loader)).is_err() {
            return false;
        }
    }
    narf_scheduler::block_on_spin(loader.stop()).is_ok()
}
pub(crate) fn resume() -> bool {
    let Some(mut guard) = DISPLAY.try_lock() else {
        return false;
    };
    let Some(display) = guard.as_mut() else {
        return true;
    };
    if narf_scheduler::current_task_id().raw() != 0 {
        return false;
    }
    use core::fmt::Write as _;
    let Display { loader, stream, .. } = display;
    if narf_scheduler::block_on_spin(async {
        loader.boot(Default::default()).await?;
        loader.enable_notifications().await
    })
    .is_err()
    {
        return false;
    }
    // Put the stream back on the mode it was validated for. The clock levels are
    // re-latched because the firmware has just rebooted, and the surface is
    // re-cleared because VRAM contents do not survive a suspend.
    if let Some(running) = stream.as_mut() {
        let replayed = narf_scheduler::block_on_spin(async {
            running.scanout.clear().await;
            running.pipeline.start().await?;
            running
                .pipeline
                .enable(
                    loader,
                    &running.scanout,
                    &running.timing,
                    &running.platform,
                    running.depth,
                    running.caps,
                )
                .await
        });
        if let Err(error) = replayed {
            // `enable` has already torn its own stream down and unpublished the
            // scanout, so the console is back on the boot framebuffer. Drop the
            // stream rather than leave a half-replayed one behind.
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu-usbc: external stream not replayed after resume: {error:?}"
            );
            *stream = None;
        }
    }
    true
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use alloc::vec;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn registers() -> Vec<u32> {
        let mut regs = vec![0; 0x910];
        for index in 0..4 {
            regs[0x5f3 + index * 0xdc] = 1;
        }
        regs
    }
    /// Every value here is read off the AMD header, never off the constant it
    /// checks: `dcn/dcn_3_1_4_offset.h`, `gc/gc_11_0_0_offset.h` and
    /// `mmhub/mmhub_3_0_1_offset.h`.
    fn platform_register_windows_match_the_amd_headers() -> TestResult {
        use crate::amdgpu_dcn as dcn;
        let last = dcn::DCN_PIPES - 1;
        // regHUBP0_DCHUBP_CNTL 0x05f3 _BASE_IDX 2; regCURSOR0_0_CURSOR_SIZE
        // 0x067b and regCURSOR0_3_CURSOR_SIZE 0x090f share that base.
        if DCN_BASE_IDX != 2 {
            return TestResult::Fail("DCN 3.1.4 puts HUBP/HUBPREQ/CURSOR on BASE_IDX 2");
        }
        if CURSOR_SIZE != 0x067b
            || CURSOR0_3_CURSOR_SIZE != 0x090f
            || dcn::for_pipe(CURSOR_SIZE, last, dcn::HUBP_PIPE_STRIDE) != CURSOR0_3_CURSOR_SIZE
        {
            return TestResult::Fail("the surface scan's upper bound is not CURSOR0_3_CURSOR_SIZE");
        }
        // regHUBP3_DCHUBP_CNTL 0x0887, regOTG3_OTG_CONTROL 0x1cc1.
        if HUBP3_DCHUBP_CNTL != 0x0887
            || dcn::for_pipe(dcn::HUBP0_DCHUBP_CNTL, last, dcn::HUBP_PIPE_STRIDE)
                != HUBP3_DCHUBP_CNTL
        {
            return TestResult::Fail("the pipe scan's hub bound is not HUBP3_DCHUBP_CNTL");
        }
        if OTG3_OTG_CONTROL != 0x1cc1
            || dcn::for_pipe(dcn::OTG0_OTG_CONTROL, last, dcn::OTG_PIPE_STRIDE) != OTG3_OTG_CONTROL
        {
            return TestResult::Fail("the pipe scan's timing bound is not OTG3_OTG_CONTROL");
        }
        // regGCVM_CONTEXT0_CNTL 0x1688 _BASE_IDX 0, regGCVM_CONTEXT15_CNTL
        // 0x1697.
        if GC_BASE_IDX != 0 || GCVM_CONTEXT0_CNTL != 0x1688 {
            return TestResult::Fail("GC 11.0.x puts GCVM_CONTEXT0_CNTL at 0x1688 on BASE_IDX 0");
        }
        if VM_CONTEXTS != 16 || GCVM_CONTEXT0_CNTL + VM_CONTEXTS - 1 != 0x1697 {
            return TestResult::Fail("GCVM_CONTEXT15_CNTL is 0x1697");
        }
        // regMMVM_CONTEXT0_CNTL 0x0740 _BASE_IDX 1, regMMVM_CONTEXT15_CNTL
        // 0x074f. `mmhub_3_0_0_offset.h` repeats those offsets on BASE_IDX 0
        // and `mmhub_3_0_2_offset.h` moves the register to 0x06c0, so a window
        // that serves 3.0.1 serves neither of the others.
        if MMHUB_BASE_IDX != 1 || MMVM_CONTEXT0_CNTL != 0x0740 {
            return TestResult::Fail("MMHUB 3.0.1 puts MMVM_CONTEXT0_CNTL at 0x0740 on BASE_IDX 1");
        }
        if MMVM_CONTEXT0_CNTL + VM_CONTEXTS - 1 != 0x074f {
            return TestResult::Fail("MMVM_CONTEXT15_CNTL is 0x074f");
        }
        if MMHUB_VERSIONS != [(3, 0, 1)] {
            return TestResult::Fail("only MMHUB 3.0.1 has this register window");
        }
        // GCVM_CONTEXT0_CNTL__ENABLE_CONTEXT and
        // MMVM_CONTEXT0_CNTL__ENABLE_CONTEXT are both 0x00000001.
        if VM_CONTEXT_ENABLE != 0x1 {
            return TestResult::Fail("ENABLE_CONTEXT is bit 0 on both hubs");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/vram",
        platform_register_windows_match_the_amd_headers
    );
    fn platform_inventory_retains_latched_surfaces_and_cursor() -> TestResult {
        let mut regs = registers();
        regs[0x5f3] = 0;
        regs[0x5e5] = 8;
        regs[0x5ea] = (768 << 16) | 1024;
        regs[0x607] = 1023;
        for (offset, address) in [
            (0x60a, 0x12000000),
            (0x621, 0x14000000),
            (0x625, 0x16000000),
        ] {
            regs[offset] = address;
            regs[offset + 1] = 2;
        }
        regs[0x678] = 1 | (2 << 8) | (1 << 16);
        regs[0x679] = 0x18000000;
        regs[0x67a] = 2;
        regs[0x67b] = (128 << 16) | 64;
        let ranges = scan_surfaces(|r| regs[r as usize]).unwrap();
        if ranges
            != [
                0x2_12000000..0x2_12300000,
                0x2_14000000..0x2_14300000,
                0x2_16000000..0x2_16300000,
                0x2_18000000..0x2_18008000,
            ]
        {
            return TestResult::Fail("in-use surfaces/cursor missing from inventory");
        }
        for (offset, value) in [
            (0x5e7, 1),
            (0x61a, 2),
            (0x609, 1),
            (0x5e5, 65),
            (0x5f3, u32::MAX),
        ] {
            let previous = regs[offset];
            regs[offset] = value;
            if scan_surfaces(|r| regs[r as usize]).is_ok() {
                return TestResult::Fail("unsupported surface ownership accepted");
            }
            regs[offset] = previous;
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/vram",
        platform_inventory_retains_latched_surfaces_and_cursor
    );
    fn platform_only_claims_a_blanked_and_stopped_pipe() -> TestResult {
        // Pipe 0 is fetching, pipe 1 is blanked but its generator still runs,
        // pipe 2 is genuinely idle.
        let state = [(0, 1), (1, 1), (1, 0), (1, 0)];
        if idle_pipe(|pipe| state[pipe as usize]) != Some(2) {
            return TestResult::Fail("claimed a pipe that was not idle");
        }
        // Every pipe busy means there is nothing to claim.
        if idle_pipe(|_| (0, 1)).is_some() || idle_pipe(|_| (1, 1)).is_some() {
            return TestResult::Fail("claimed a busy pipe");
        }
        // A vanished device is not four idle pipes.
        if idle_pipe(|_| (u32::MAX, u32::MAX)).is_some() || idle_pipe(|_| (1, u32::MAX)).is_some() {
            return TestResult::Fail("claimed a pipe on a vanished device");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/vram",
        platform_only_claims_a_blanked_and_stopped_pipe
    );
}
