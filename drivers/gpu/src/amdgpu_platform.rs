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
// block or of its instance. The fifth is the highest dword read through that
// base, which `bank` bounds-checks against the BAR.
//
// Each of the three IPs this file reads gets a table with one row per
// supported version, resolved against the discovery blob by
// `amdgpu_psp_ring::bank_for`. Sibling revisions of the same IP move both base
// indices and offsets, so a row covers exactly one version and an unlisted one
// is `Unsupported` rather than silently borrowing a neighbour's window.
// Supporting another GPU is adding rows here (and, for DCN, the modeset table
// in `amdgpu_dcn`).

/// Both VM hubs carry sixteen contexts one dword apart
/// (`regGCVM_CONTEXT1_CNTL` 0x1689 against 0x1688, `regMMVM_CONTEXT1_CNTL`
/// 0x0741 against 0x0740), each with `ENABLE_CONTEXT` in bit 0.
const VM_CONTEXTS: u32 = 16;
const VM_CONTEXT_ENABLE: u32 = 1 << 0;

/// One VM hub's `*VM_CONTEXT0_CNTL` window.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct VmWindow {
    version: (u8, u8, u8),
    base_idx: usize,
    ctx0_cntl: u32,
}
impl crate::amdgpu_psp_ring::RegWindow for VmWindow {
    fn version(&self) -> (u8, u8, u8) {
        self.version
    }
    fn base_idx(&self) -> usize {
        self.base_idx
    }
    fn last(&self) -> u32 {
        self.ctx0_cntl + VM_CONTEXTS - 1
    }
}

/// `gc/gc_11_0_0_offset.h` serves every GC 11.0.x — `gfx_v11_0.c` includes it
/// unconditionally — and puts `regGCVM_CONTEXT0_CNTL` at 0x1688 on
/// `_BASE_IDX 0`, running to `regGCVM_CONTEXT15_CNTL` 0x1697.
const GFXHUB_WINDOWS: &[VmWindow] = &[
    // Phoenix1 (780M).
    VmWindow {
        version: (11, 0, 1),
        base_idx: 0,
        ctx0_cntl: 0x1688,
    },
    // Phoenix2.
    VmWindow {
        version: (11, 0, 4),
        base_idx: 0,
        ctx0_cntl: 0x1688,
    },
];

/// The MMHUB 3.0.x headers share no window, which is why this is a table and
/// not a constant: all three name `regMMVM_CONTEXT0_CNTL`, and no two of them
/// agree on where it is.
///
/// This was one `_BASE_IDX 0` + 0x0740 pair accepted for all three versions.
/// On the hardware we target that read the wrong segment, so the sixteen reads
/// that decide whether a VM client is live landed somewhere unrelated and the
/// handoff either refused a quiescent GPU — leaving the panel on the UEFI
/// framebuffer — or admitted a live VM context, on whatever bit 0 those dwords
/// happened to carry. `amdgpu_vmhub_regs` already recorded that this
/// generation's MMHUB is BASE_IDX 1.
const MMHUB_WINDOWS: &[VmWindow] = &[
    // `mmhub_3_0_0_offset.h` — Navi3x (`mmhub_v3_0.c`).
    VmWindow {
        version: (3, 0, 0),
        base_idx: 0,
        ctx0_cntl: 0x0740,
    },
    // `mmhub_3_0_1_offset.h` — Phoenix. Linux `gmc_v11_0.c:578` selects
    // `mmhub_v3_0_1_funcs`, and `mmhub_v3_0_1.c:27` includes this header: the
    // same offsets as 3.0.0 on `_BASE_IDX` **1**.
    VmWindow {
        version: (3, 0, 1),
        base_idx: 1,
        ctx0_cntl: 0x0740,
    },
    // `mmhub_3_0_2_offset.h` — 3.0.0's base index, but the register moved.
    VmWindow {
        version: (3, 0, 2),
        base_idx: 0,
        ctx0_cntl: 0x06c0,
    },
];

/// One DCN version's inherited-scanout window: every register `scan_surfaces`
/// and `free_pipe` read, since a DCN revision may move any of them.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct SurfaceWindow {
    version: (u8, u8, u8),
    base_idx: usize,
    /// `regHUBP0_DCSURF_SURFACE_CONFIG`.
    surface_config: u32,
    /// `regHUBP0_DCSURF_TILING_CONFIG`.
    tiling_config: u32,
    /// `regHUBP0_DCSURF_PRI_VIEWPORT_START`.
    viewport_start: u32,
    /// `regHUBP0_DCSURF_PRI_VIEWPORT_DIMENSION`.
    viewport_dimension: u32,
    /// `regHUBP0_DCHUBP_CNTL`.
    hubp_cntl: u32,
    /// `regHUBPREQ0_DCSURF_SURFACE_PITCH`.
    surface_pitch: u32,
    /// `regHUBPREQ0_VMID_SETTINGS_0`.
    vmid_settings: u32,
    /// `regHUBPREQ0_DCSURF_PRIMARY_SURFACE_ADDRESS` (+1 = `_HIGH`).
    primary_address: u32,
    /// `regHUBPREQ0_DCSURF_SECONDARY_SURFACE_ADDRESS` (+1 = `_HIGH`).
    secondary_address: u32,
    /// `regHUBPREQ0_DCSURF_SURFACE_CONTROL`.
    surface_control: u32,
    /// `regHUBPREQ0_DCSURF_SURFACE_INUSE` (+1 = `_HIGH`).
    surface_inuse: u32,
    /// `regHUBPREQ0_DCSURF_SURFACE_EARLIEST_INUSE` (+1 = `_HIGH`).
    surface_earliest_inuse: u32,
    /// `regCURSOR0_0_CURSOR_CONTROL`.
    cursor_control: u32,
    /// `regCURSOR0_0_CURSOR_SURFACE_ADDRESS` (+1 = `_HIGH`).
    cursor_address: u32,
    /// `regCURSOR0_0_CURSOR_SIZE`.
    cursor_size: u32,
    /// `regOTG0_OTG_CONTROL`.
    otg_control: u32,
    /// How many HUBP/CURSOR/OTG instances the ASIC has.
    pipes: u8,
    /// Dword distance between HUBP/HUBPREQ/CURSOR instances.
    pipe_stride: u32,
    /// Dword distance between OTG instances.
    otg_stride: u32,
}
impl SurfaceWindow {
    /// Highest dword any reader of this window touches: the last pipe's
    /// `OTG_CONTROL`. The timing generators sit far above the hubs, so this
    /// bounds the surface scan's last `CURSOR_SIZE` and the pipe scan's last
    /// `DCHUBP_CNTL` as well — on DCN 3.1.4, `regOTG3_OTG_CONTROL` 0x1cc1
    /// against `regCURSOR0_3_CURSOR_SIZE` 0x090f and `regHUBP3_DCHUBP_CNTL`
    /// 0x0887.
    const fn last_reg(&self) -> u32 {
        self.otg_control + (self.pipes as u32 - 1) * self.otg_stride
    }
}
impl crate::amdgpu_psp_ring::RegWindow for SurfaceWindow {
    fn version(&self) -> (u8, u8, u8) {
        self.version
    }
    fn base_idx(&self) -> usize {
        self.base_idx
    }
    fn last(&self) -> u32 {
        self.last_reg()
    }
}

/// `dcn/dcn_3_1_4_offset.h` — Phoenix. Everything the scan reads is
/// `_BASE_IDX 2`.
const DCN_3_1_4: SurfaceWindow = SurfaceWindow {
    version: (3, 1, 4),
    base_idx: 2,
    surface_config: 0x05e5,
    tiling_config: 0x05e7,
    viewport_start: 0x05e9,
    viewport_dimension: 0x05ea,
    hubp_cntl: 0x05f3,
    surface_pitch: 0x0607,
    vmid_settings: 0x0609,
    primary_address: 0x060a,
    secondary_address: 0x060e,
    surface_control: 0x061a,
    surface_inuse: 0x0621,
    surface_earliest_inuse: 0x0625,
    cursor_control: 0x0678,
    cursor_address: 0x0679,
    cursor_size: 0x067b,
    otg_control: 0x1b41,
    pipes: 4,
    pipe_stride: 0xdc,
    otg_stride: 0x80,
};

/// `dcn/dcn_3_5_0_offset.h` — Strix / HawkPoint, the other display generation
/// `amdgpu_dcn` carries a modeset table for.
///
/// This is why the window is a table rather than one set of constants: DCN 3.5
/// shifts `DCSURF_SURFACE_INUSE` and `DCSURF_SURFACE_EARLIEST_INUSE` one dword
/// **down** from 3.1.4's (0x0620/0x0624 against 0x0621/0x0625 — 3.1.4's
/// `SURFACE_FLIP_INTERRUPT` at 0x0620 is gone), and moves `OTG0_OTG_CONTROL`
/// from 0x1b41 to 0x1b43. Reading 3.1.4's ids on a 3.5 part would take
/// `INUSE_HIGH` for the low half of an address and `INUSE_C` for its high
/// half. Every other id below is identical in both headers.
const DCN_3_5_0: SurfaceWindow = SurfaceWindow {
    version: (3, 5, 0),
    surface_inuse: 0x0620,
    surface_earliest_inuse: 0x0624,
    otg_control: 0x1b43,
    ..DCN_3_1_4
};

const SURFACE_WINDOWS: &[SurfaceWindow] = &[DCN_3_1_4, DCN_3_5_0];

// Field masks. `dcn_3_1_4_sh_mask.h` and `dcn_3_5_0_sh_mask.h` agree on every
// one of these, so they are not part of the per-version window:
//
//   SURFACE_PIXEL_FORMAT        0x0000007f   SW_MODE              0x0000001f
//   PRI_VIEWPORT_X/Y_START      0x00003fff   WIDTH/HEIGHT         0x3fff0000
//   PITCH                       0x00003fff   VMID                 0x0000000f
//   HUBP_BLANK_EN               0x00000001   OTG_MASTER_EN        0x00000001
//   CURSOR_ENABLE               0x00000001   CURSOR_MODE          0x00000700
//   CURSOR_TMZ                  0x00001000   CURSOR_PITCH         0x00030000
//   CURSOR_HEIGHT               0x000001ff   CURSOR_WIDTH         0x01ff0000
//   *_SURFACE_ADDRESS_HIGH      0x0000ffff
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

/// Production boot has not initialized GFX/GART or other driver VRAM clients.
/// Reject live VM contexts rather than guessing the size of inherited tables.
fn inventory(gpu: &AmdGpu, cap: &Cap<BusDeviceCap, Write>) -> Result<Vec<Range<u64>>, Error> {
    use crate::amdgpu_discovery as ip;
    use crate::amdgpu_psp_ring::bank_for;
    let (dcn, surface) = bank_for(gpu, ip::HW_ID_DCN, SURFACE_WINDOWS).map_err(Error::Psp)?;
    let (gc, gfxhub) = bank_for(gpu, ip::HW_ID_GC, GFXHUB_WINDOWS).map_err(Error::Psp)?;
    let (hub, mmhub) = bank_for(gpu, ip::HW_ID_MMHUB, MMHUB_WINDOWS).map_err(Error::Psp)?;
    if gpu.fw_loaded || gpu.mode.is_some() {
        return Err(Error::Busy);
    }
    cap.invoke(Op(|| {
        for (base, first) in [(gc, gfxhub.ctx0_cntl), (hub, mmhub.ctx0_cntl)] {
            for index in 0..u64::from(VM_CONTEXTS) {
                // SAFETY: exact IP bank and entire context array bounded above.
                let value = unsafe { gpu.regs.read32(base + (u64::from(first) + index) * 4) };
                if value == u32::MAX || value & VM_CONTEXT_ENABLE != 0 {
                    return Err(Error::Busy);
                }
            }
        }
        // SAFETY: bank validation bounds every HUBP/cursor instance.
        scan_surfaces(&surface, |reg| unsafe {
            gpu.regs.read32(dcn + reg as u64 * 4)
        })
    }))
    .map_err(|_| Error::Revoked)?
}
fn scan_surfaces(
    window: &SurfaceWindow,
    mut read: impl FnMut(u32) -> u32,
) -> Result<Vec<Range<u64>>, Error> {
    let mut ranges = Vec::new();
    let mut read = |reg| {
        let v = read(reg);
        if v == u32::MAX {
            Err(Error::Invalid)
        } else {
            Ok(v)
        }
    };
    for index in 0..u32::from(window.pipes) {
        let delta = index * window.pipe_stride;
        if read(window.hubp_cntl + delta)? & crate::amdgpu_dcn::HUBP_BLANK_FORCE == 0 {
            // Only packed, linear RGB is a bounded inherited scanout here.
            // Reject DCC/YUV/stereo/VM surfaces instead of overlooking metadata.
            //
            // `hubp1_program_pixel_format` in Linux
            // `display/dc/hubp/dcn10/dcn10_hubp.c` is the encoding: 1 ARGB1555
            // and 3 RGB565 are two bytes, 8 A*GB8888 and 10 A*GB2101010 four,
            // 24 ARGB16161616F and 26 ARGB16161616_UNORM eight. 12
            // (AYCrCb8888), 65..=67 (420 YCbCr/YCrCb) and 112..=119 are the
            // YUV and packed-float formats this handoff will not size.
            let format = read(window.surface_config + delta)? & SURFACE_PIXEL_FORMAT;
            let bpp = match format {
                1 | 3 => 2,
                8 | 10 => 4,
                24 | 26 => 8,
                _ => return Err(Error::Unsupported),
            };
            if read(window.tiling_config + delta)? & SW_MODE != 0
                || read(window.surface_control + delta)? & SURFACE_PROTECTED_OR_COMPRESSED != 0
                || read(window.vmid_settings + delta)? & VMID != 0
            {
                return Err(Error::Unsupported);
            }
            let viewport = read(window.viewport_dimension + delta)?;
            let start = read(window.viewport_start + delta)?;
            let pitch = (read(window.surface_pitch + delta)? & PITCH) + 1;
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
                window.primary_address,
                window.secondary_address,
                window.surface_inuse,
                window.surface_earliest_inuse,
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
        let control = read(window.cursor_control + delta)?;
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
            let size = read(window.cursor_size + delta)?;
            let rows = size & CURSOR_DIM;
            let width = (size >> 16) & CURSOR_DIM;
            let pitch = 64u64 << ((control >> CURSOR_PITCH_SHIFT) & CURSOR_PITCH);
            if rows == 0 || width == 0 || width as u64 > pitch || pitch > 256 {
                return Err(Error::Invalid);
            }
            let address = read(window.cursor_address + delta)? as u64
                | (read(window.cursor_address + 1 + delta)? as u64) << 32;
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
fn idle_pipe(pipes: u8, mut state: impl FnMut(u8) -> (u32, u32)) -> Option<u8> {
    for pipe in 0..pipes {
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
    let (dcn, window) =
        crate::amdgpu_psp_ring::bank_for(gpu, ip::HW_ID_DCN, SURFACE_WINDOWS).ok()?;
    cap.invoke(Op(|| {
        idle_pipe(window.pipes, |pipe| {
            let hub_reg = crate::amdgpu_dcn::for_pipe(window.hubp_cntl, pipe, window.pipe_stride);
            let otg_reg = crate::amdgpu_dcn::for_pipe(window.otg_control, pipe, window.otg_stride);
            // SAFETY: the bank is bounded above every instance of both blocks.
            unsafe {
                (
                    gpu.regs.read32(dcn + u64::from(hub_reg) * 4),
                    gpu.regs.read32(dcn + u64::from(otg_reg) * 4),
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
    /// Every literal here is read off the AMD header, never off the row it
    /// checks. One case per row, so adding a GPU means adding a case: a new
    /// row with no case is a window nothing has verified.
    fn platform_register_windows_match_the_amd_headers() -> TestResult {
        // `gc/gc_11_0_0_offset.h`: regGCVM_CONTEXT0_CNTL 0x1688 _BASE_IDX 0,
        // regGCVM_CONTEXT15_CNTL 0x1697. Both GC 11.0.x revisions use it.
        let gfxhub_expected = [
            VmWindow {
                version: (11, 0, 1),
                base_idx: 0,
                ctx0_cntl: 0x1688,
            },
            VmWindow {
                version: (11, 0, 4),
                base_idx: 0,
                ctx0_cntl: 0x1688,
            },
        ];
        if GFXHUB_WINDOWS != gfxhub_expected {
            return TestResult::Fail("a GFXHUB row does not match gc_11_0_0_offset.h");
        }
        // mmhub_3_0_0_offset.h: 0x0740 _BASE_IDX 0.
        // mmhub_3_0_1_offset.h: 0x0740 _BASE_IDX 1.
        // mmhub_3_0_2_offset.h: 0x06c0 _BASE_IDX 0.
        let mmhub_expected = [
            VmWindow {
                version: (3, 0, 0),
                base_idx: 0,
                ctx0_cntl: 0x0740,
            },
            VmWindow {
                version: (3, 0, 1),
                base_idx: 1,
                ctx0_cntl: 0x0740,
            },
            VmWindow {
                version: (3, 0, 2),
                base_idx: 0,
                ctx0_cntl: 0x06c0,
            },
        ];
        if MMHUB_WINDOWS != mmhub_expected {
            return TestResult::Fail("an MMHUB row does not match its mmhub_3_0_x_offset.h");
        }
        // regGCVM_CONTEXT15_CNTL 0x1697, regMMVM_CONTEXT15_CNTL 0x074f: both
        // hubs run sixteen contexts one dword apart, and the window's `last`
        // must reach the sixteenth.
        if VM_CONTEXTS != 16 || VM_CONTEXT_ENABLE != 0x1 {
            return TestResult::Fail("sixteen contexts, ENABLE_CONTEXT in bit 0");
        }
        {
            use crate::amdgpu_psp_ring::RegWindow as _;
            if GFXHUB_WINDOWS[0].last() != 0x1697 || MMHUB_WINDOWS[1].last() != 0x074f {
                return TestResult::Fail("a VM window stops short of CONTEXT15_CNTL");
            }
        }
        // dcn/dcn_3_1_4_offset.h. Every id is _BASE_IDX 2.
        let dcn314_expected = SurfaceWindow {
            version: (3, 1, 4),
            base_idx: 2,
            surface_config: 0x05e5,
            tiling_config: 0x05e7,
            viewport_start: 0x05e9,
            viewport_dimension: 0x05ea,
            hubp_cntl: 0x05f3,
            surface_pitch: 0x0607,
            vmid_settings: 0x0609,
            primary_address: 0x060a,
            secondary_address: 0x060e,
            surface_control: 0x061a,
            surface_inuse: 0x0621,
            surface_earliest_inuse: 0x0625,
            cursor_control: 0x0678,
            cursor_address: 0x0679,
            cursor_size: 0x067b,
            otg_control: 0x1b41,
            pipes: 4,
            pipe_stride: 0xdc,
            otg_stride: 0x80,
        };
        // dcn/dcn_3_5_0_offset.h. Identical except for the two in-use reports
        // and OTG_CONTROL, which is the whole reason this is a table.
        let dcn350_expected = SurfaceWindow {
            version: (3, 5, 0),
            surface_inuse: 0x0620,
            surface_earliest_inuse: 0x0624,
            otg_control: 0x1b43,
            ..dcn314_expected
        };
        if SURFACE_WINDOWS != [dcn314_expected, dcn350_expected] {
            return TestResult::Fail("a DCN row does not match its dcn_x_y_z_offset.h");
        }
        if dcn314_expected.surface_inuse == dcn350_expected.surface_inuse
            || dcn314_expected.otg_control == dcn350_expected.otg_control
        {
            return TestResult::Fail("these are the ids the two DCN headers disagree on");
        }
        // regHUBP1_DCHUBP_CNTL 0x06cf against 0x05f3; regOTG1_OTG_CONTROL
        // 0x1bc1 against 0x1b41. regHUBP3_DCHUBP_CNTL 0x0887,
        // regCURSOR0_3_CURSOR_SIZE 0x090f, regOTG3_OTG_CONTROL 0x1cc1 — the
        // bound has to clear all three, and 3.5's OTG3 is 0x1cc3.
        let w = DCN_3_1_4;
        if w.hubp_cntl + w.pipe_stride != 0x06cf || w.otg_control + w.otg_stride != 0x1bc1 {
            return TestResult::Fail("a DCN 3.1.4 pipe stride is wrong");
        }
        let top = u32::from(w.pipes - 1);
        if w.hubp_cntl + top * w.pipe_stride != 0x0887
            || w.cursor_size + top * w.pipe_stride != 0x090f
            || w.last_reg() != 0x1cc1
        {
            return TestResult::Fail("DCN 3.1.4's bank bound is not OTG3_OTG_CONTROL");
        }
        if DCN_3_5_0.last_reg() != 0x1cc3 {
            return TestResult::Fail("DCN 3.5's bank bound is not its own OTG3_OTG_CONTROL");
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
        let ranges = scan_surfaces(&DCN_3_1_4, |r| regs[r as usize]).unwrap();
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
            if scan_surfaces(&DCN_3_1_4, |r| regs[r as usize]).is_ok() {
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
        if idle_pipe(DCN_3_1_4.pipes, |pipe| state[pipe as usize]) != Some(2) {
            return TestResult::Fail("claimed a pipe that was not idle");
        }
        // Every pipe busy means there is nothing to claim.
        if idle_pipe(DCN_3_1_4.pipes, |_| (0, 1)).is_some()
            || idle_pipe(DCN_3_1_4.pipes, |_| (1, 1)).is_some()
        {
            return TestResult::Fail("claimed a busy pipe");
        }
        // A vanished device is not four idle pipes.
        if idle_pipe(DCN_3_1_4.pipes, |_| (u32::MAX, u32::MAX)).is_some()
            || idle_pipe(DCN_3_1_4.pipes, |_| (1, u32::MAX)).is_some()
        {
            return TestResult::Fail("claimed a pipe on a vanished device");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/vram",
        platform_only_claims_a_blanked_and_stopped_pipe
    );
}
