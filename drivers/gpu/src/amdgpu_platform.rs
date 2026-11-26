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
struct OpenToc(&'static str);
impl CapOp<narf_firmware::FirmwareRegistry, Read> for OpenToc {
    type Output = Result<Vec<u8>, Error>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self::Output, CapError> {
        let blob = match narf_firmware::open(self.0, cap) {
            Ok(blob) => blob,
            Err(_) => return Ok(Err(Error::Invalid)),
        };
        blob.invoke(CopyToc)
    }
}
struct CopyAsd;
impl CapOp<narf_firmware::FirmwareBlob, Read> for CopyAsd {
    type Output = Result<Vec<u8>, Error>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareBlob, Read>,
    ) -> Result<Self::Output, CapError> {
        Ok((|| {
            let view = narf_firmware::view_of(cap).map_err(|_| Error::Invalid)?;
            crate::amdgpu_psp_ring::asd_payload(view.bytes).map_err(Error::Psp)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(view.bytes.len())
                .map_err(|_| Error::Allocation)?;
            bytes.extend_from_slice(view.bytes);
            Ok(bytes)
        })())
    }
}
struct OpenAsd(&'static str);
impl CapOp<narf_firmware::FirmwareRegistry, Read> for OpenAsd {
    type Output = Result<Vec<u8>, Error>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self::Output, CapError> {
        let blob = match narf_firmware::open(self.0, cap) {
            Ok(blob) => blob,
            Err(_) => return Ok(Err(Error::Invalid)),
        };
        blob.invoke(CopyAsd)
    }
}

/// The PSP image `prepare()` authenticated: a standalone TOC for PSP
/// 13.0.4/13.0.5, or the ASD container for PSP 12.0 (Renoir/Cezanne),
/// which loads ASD + TA only and has no TOC.
enum PspImage {
    Toc(Vec<u8>),
    Asd(Vec<u8>),
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
/// `_BASE_IDX 0`, running to `regGCVM_CONTEXT15_CNTL` 0x1697. Navi32's
/// GC 11.0.3 is the exception: `gc_11_0_3_offset.h` puts the whole
/// GCMC/GCVM block 0x10 higher (`amdgpu_gmc_navi31_regs`), so its
/// CONTEXT0 sits at 0x1698.
const GFXHUB_WINDOWS: &[VmWindow] = &[
    // gc_12_0_0_offset.h, GC12.0.1 (Navi48); GC12.0.0 (Navi44) is last.
    VmWindow {
        version: (12, 0, 1),
        base_idx: 0,
        ctx0_cntl: 0x1624,
    },
    // Navi31 (RX 7900), GC 11.0.0.
    VmWindow {
        version: (11, 0, 0),
        base_idx: 0,
        ctx0_cntl: 0x1688,
    },
    // Navi33 (RX 7600), GC 11.0.2: Linux drives it with the 11.0.0
    // function table (`gmc_v11_0_set_gfxhub_funcs`).
    VmWindow {
        version: (11, 0, 2),
        base_idx: 0,
        ctx0_cntl: 0x1688,
    },
    // Navi32 (RX 7800 XT), GC 11.0.3: the block sits 0x10 higher.
    VmWindow {
        version: (11, 0, 3),
        base_idx: 0,
        ctx0_cntl: 0x1698,
    },
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
    // Discrete GC10.3 shares gfxhub_v2_1 context windows.
    VmWindow {
        version: (10, 3, 0),
        base_idx: 0,
        ctx0_cntl: 0x15fc,
    },
    VmWindow {
        version: (10, 3, 4),
        base_idx: 0,
        ctx0_cntl: 0x15fc,
    },
    VmWindow {
        version: (10, 3, 5),
        base_idx: 0,
        ctx0_cntl: 0x15fc,
    },
    // Raphael: gmc_v10_0.c gives GC 10.3.6 gfxhub_v2_1, gc_10_3_0_offset.h.
    VmWindow {
        version: (10, 3, 6),
        base_idx: 0,
        ctx0_cntl: 0x15fc,
    },
    // Navi22, gc_10_3_0_offset.h: CONTEXT0..15 at 0x15fc..0x160b.
    VmWindow {
        version: (10, 3, 2),
        base_idx: 0,
        ctx0_cntl: 0x15fc,
    },
    // Navi44: gc_12_0_0_offset.h serves both RDNA4 dies.
    VmWindow {
        version: (12, 0, 0),
        base_idx: 0,
        ctx0_cntl: 0x1624,
    },
    // Renoir / Cezanne: `gmc_v9_0_set_gfxhub_funcs` gives every
    // non-multi-AID GFX9 part `gfxhub_v1_0_funcs`; `gc_9_0_offset.h`
    // puts `mmVM_CONTEXT0_CNTL` at 0x0880 on `_BASE_IDX` 0.
    VmWindow {
        version: (9, 3, 0),
        base_idx: 0,
        ctx0_cntl: 0x0880,
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
    // mmhub_4_1_0_offset.h, selected by gmc_v12_0.c.
    VmWindow {
        version: (4, 1, 0),
        base_idx: 0,
        ctx0_cntl: 0x0564,
    },
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
    VmWindow {
        version: (2, 1, 1),
        base_idx: 0,
        ctx0_cntl: 0x06c0,
    },
    VmWindow {
        version: (2, 1, 2),
        base_idx: 0,
        ctx0_cntl: 0x06c0,
    },
    // Raphael's MMHUB is one of the versions gmc_v10_0.c gives mmhub_v2_3,
    // which includes mmhub_2_3_0_offset.h: mmMMVM_CONTEXT0_CNTL 0x0740 on
    // _BASE_IDX 1.
    VmWindow {
        version: (2, 3, 0),
        base_idx: 1,
        ctx0_cntl: 0x0740,
    },
    VmWindow {
        version: (2, 4, 0),
        base_idx: 1,
        ctx0_cntl: 0x0740,
    },
    VmWindow {
        version: (2, 4, 1),
        base_idx: 1,
        ctx0_cntl: 0x0740,
    },
    // GMC10's MMHUB2.1 uses mmhub_v2_0 / mmhub_2_0_0_offset.h.
    VmWindow {
        version: (2, 1, 0),
        base_idx: 0,
        ctx0_cntl: 0x06c0,
    },
];

/// GFX9's MMHUB table (`gmc_v9_0.c` includes
/// `mmhub/mmhub_1_0_offset.h` and sends both MMHUB (1, 5, 0) and
/// (2, 4, 0) to `mmhub_v1_0_funcs`). There is no
/// `mmhub_1_5_0_offset.h` in Linux: on GFX9 both versions are the
/// v1.0 layout, `mmVM_CONTEXT0_CNTL` 0x06c0 on `_BASE_IDX` 0.
/// MMHUB (2, 4, 0) is ambiguous across generations — the GFX10 table
/// above carries it at 0x0740/base 1 — so `inventory` selects this
/// table when the GC bank is 9.x.
const MMHUB_WINDOWS_GFX9: &[VmWindow] = &[
    VmWindow {
        version: (1, 5, 0),
        base_idx: 0,
        ctx0_cntl: 0x06c0,
    },
    VmWindow {
        version: (2, 4, 0),
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
    viewport_start_mask: u32,
    pitch_mask: u32,
    sw_mode_mask: u32,
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
    viewport_start_mask: 0x3fff,
    pitch_mask: 0x3fff,
    sw_mode_mask: 0x1f,
};

/// `dcn/dcn_3_1_5_offset.h` — Raphael. Every HUBP, cursor and OTG_CONTROL
/// register the scan reads keeps its DCN 3.1.4 offset, and every mask agrees.
const DCN_3_1_5: SurfaceWindow = SurfaceWindow {
    version: (3, 1, 5),
    ..DCN_3_1_4
};

/// `dcn/dcn_3_5_0_offset.h` — Strix, the other display generation
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

// dcn_3_0_0_offset.h has the same surface offsets and instance strides as
// DCN314, but dcn30_resource.c supplies SIX pipes, ending at OTG5 0x1dc1.
const DCN_3_0_0: SurfaceWindow = SurfaceWindow {
    version: (3, 0, 0),
    pipes: 6,
    ..DCN_3_1_4
};
// dcn_4_1_0 headers implement Linux's normalized DCN4.0.1 resource.
// Viewport starts/pitch expand to 16 bits; dimensions remain 14 bits.
const DCN_4_0_1: SurfaceWindow = SurfaceWindow {
    version: (4, 0, 1),
    viewport_dimension: 0x05eb,
    hubp_cntl: 0x05f4,
    surface_control: 0x0612,
    surface_inuse: 0x0618,
    surface_earliest_inuse: 0x061c,
    cursor_control: 0x0679,
    cursor_address: 0x067a,
    cursor_size: 0x067c,
    otg_control: 0x1b43,
    viewport_start_mask: 0xffff,
    pitch_mask: 0xffff,
    sw_mode_mask: 7,
    ..DCN_3_1_4
};
const DCN_4_1_0: SurfaceWindow = SurfaceWindow {
    version: (4, 1, 0),
    ..DCN_4_0_1
};
const DCN_3_0_2: SurfaceWindow = SurfaceWindow {
    version: (3, 0, 2),
    pipes: 5,
    ..DCN_3_0_0
};
const DCN_3_0_3: SurfaceWindow = SurfaceWindow {
    version: (3, 0, 3),
    pipes: 2,
    ..DCN_3_0_0
};
/// `dcn/dcn_2_1_0_offset.h` — Renoir / Cezanne. DCN 2.1 shares DCN
/// 2.0's surface window: every HUBP/cursor/OTG register the scan
/// reads sits at the same offset as in DCN 3.1.4 (HUBP stride 0xdc,
/// OTG stride 0x80), and `dcn21_resource.c` supplies the same 4
/// pipes as DCN 3.1.4.
///
/// The APU audit claimed Renoir is DCN 2.0; `dc_resource.c` maps both
/// ASICREV_IS_RENOIR and ASICREV_IS_GREEN_SARDINE to DCN_VERSION_2_1,
/// and the kernel APU table agrees — so this row is (2, 1, 0), and a
/// (2, 0, 0) blob is refused fail-closed rather than driven as 2.1.
/// (A version-keyed (2, 0, 0) row would also match Navi10/14
/// discrete parts with the wrong pipe counts.)
const DCN_2_1_0: SurfaceWindow = SurfaceWindow {
    version: (2, 1, 0),
    ..DCN_3_1_4
};
/// `dcn/dcn_3_2_0_offset.h` and `dcn_3_2_1_offset.h` agree with 3.1.4 on
/// every register this scan reads (`amdgpu_dcn_inventory` groups
/// Dcn320/Dcn321 with Dcn314; the Navi31 modeset fixture reads
/// OTG_CONTROL at 0x1b41 with the 3.1.4 stride 0x80). Four pipes, as on
/// 3.1.4.
const DCN_3_2_0: SurfaceWindow = SurfaceWindow {
    version: (3, 2, 0),
    ..DCN_3_1_4
};
const DCN_3_2_1: SurfaceWindow = SurfaceWindow {
    version: (3, 2, 1),
    ..DCN_3_1_4
};
const SURFACE_WINDOWS: &[SurfaceWindow] = &[
    DCN_3_0_2, DCN_3_0_3, DCN_3_1_4, DCN_3_1_5, DCN_3_2_0, DCN_3_2_1, DCN_3_5_0, DCN_3_0_0,
    DCN_4_0_1, DCN_4_1_0, DCN_2_1_0,
];

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
/// `PRIMARY_SURFACE_TMZ` | `PRIMARY_SURFACE_DCC_EN` |
/// `SECONDARY_SURFACE_TMZ` | `SECONDARY_SURFACE_DCC_EN`. With DCC off there is
/// no metadata surface to account for.
const SURFACE_PROTECTED_OR_COMPRESSED: u32 = 0x0303;
const VMID: u32 = 0xf;
const VIEWPORT_COORD: u32 = 0x3fff;
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
    // MMHUB (2, 4, 0) is ambiguous: on GFX9 (`gmc_v9_0`) it is the v1.0
    // layout (0x06c0, base 0), on GFX10 (`gmc_v10_0`) the v2.3 layout
    // (0x0740, base 1). The GC bank's major version selects the table.
    let mmhub_windows = if gfxhub.version.0 == 9 {
        MMHUB_WINDOWS_GFX9
    } else {
        MMHUB_WINDOWS
    };
    let (hub, mmhub) = bank_for(gpu, ip::HW_ID_MMHUB, mmhub_windows).map_err(Error::Psp)?;
    if gpu.fw_loaded || gpu.mode.is_some() {
        return Err(Error::Busy);
    }
    // Firmware/GOP may leave the kernel context VMID0 enabled on a discrete
    // Navi22; no engine runs in it and gmc_v10_0_gart_enable reprograms it,
    // so only user contexts 1..15 mean unknown live page tables there.
    let first_context =
        u64::from(crate::amdgpu_rdna2::for_pci_id(gpu.chip.vid, gpu.chip.did).is_some());
    cap.invoke(Op(|| {
        for (base, first) in [(gc, gfxhub.ctx0_cntl), (hub, mmhub.ctx0_cntl)] {
            for index in first_context..u64::from(VM_CONTEXTS) {
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
pub(crate) fn boot_clients(
    gpu: &AmdGpu,
    cap: &Cap<BusDeviceCap, Write>,
) -> Result<Vec<Range<u64>>, crate::amdgpu_vram_boot::Error> {
    use crate::amdgpu_vram_boot::Error as MemoryError;
    inventory(gpu, cap).map_err(|error| match error {
        Error::Busy => MemoryError::Busy,
        Error::Revoked => MemoryError::Revoked,
        Error::Invalid => MemoryError::Invalid,
        _ => MemoryError::Unsupported,
    })
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
        // dcn10_init_pipes: only a pipe whose timing generator runs
        // (is_tg_enabled, OTG_MASTER_EN) scans out; a disabled TG's pipe is
        // powered down whatever its HUBP blank state says.
        let otg = read(window.otg_control + index * window.otg_stride)?;
        if otg & crate::amdgpu_dcn::OTG_MASTER_EN == 0 {
            continue;
        }
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
            if read(window.tiling_config + delta)? & window.sw_mode_mask != 0
                || read(window.surface_control + delta)? & SURFACE_PROTECTED_OR_COMPRESSED != 0
                || read(window.vmid_settings + delta)? & VMID != 0
            {
                return Err(Error::Unsupported);
            }
            let viewport = read(window.viewport_dimension + delta)?;
            let start = read(window.viewport_start + delta)?;
            let pitch = (read(window.surface_pitch + delta)? & window.pitch_mask) + 1;
            let rows =
                ((start >> 16) & window.viewport_start_mask) + ((viewport >> 16) & VIEWPORT_COORD);
            if rows == 0
                || (viewport & VIEWPORT_COORD) == 0
                || (start & window.viewport_start_mask) + (viewport & VIEWPORT_COORD) > pitch
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
/// authority, the firmware registry and the PSP image.
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

/// The boot handoff: the VRAM plan, the pool and the PSP/DMUB loader.
/// Out of line: inlined, its firmware, plan, pool and loader temporaries
/// join [`start`]'s frame beside the display task's future and pass the
/// 8 KiB kernel frame budget (`build/frame-budget.txt`).
#[inline(never)]
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
    // psp_init_toc_microcode: the TOC is named for the PSP's own version.
    // PSP 12.0 (Renoir MP0 11.0.3, Cezanne MP0 12.0.1) has no TOC: its
    // PSP image is the ASD container (`psp_v12_0_init_microcode` loads
    // ASD + TA only).
    let psp_image = crate::amdgpu::with_controller(|gpu| {
        let mp0 = crate::amdgpu_discovery::find_ip(
            &gpu.ip_blocks,
            crate::amdgpu_discovery::HW_ID_MP0,
            0,
        )?;
        match (mp0.major, mp0.minor, mp0.revision) {
            (13, 0, 4) => Some(("amdgpu/psp_13_0_4_toc.bin", true)),
            (13, 0, 5) => Some(("amdgpu/psp_13_0_5_toc.bin", true)),
            (11, 0, 3) => Some(("amdgpu/renoir_asd.bin", false)),
            (12, 0, 1) => Some(("amdgpu/green_sardine_asd.bin", false)),
            // Rembrandt: MP0 13.0.1 and 13.0.3 both decode to the `yellow_carp`
            // legacy name (`amdgpu_ucode_legacy_naming`), so both load the
            // same TOC (`psp_v13_0.c`).
            (13, 0, 1) | (13, 0, 3) => Some(("amdgpu/yellow_carp_toc.bin", true)),
            // MP0 14.0.0 / 14.0.1 (Strix) take the `psp_v13_0` TOC branch
            // (`psp_v13_0.c`: `case IP_VERSION(14, 0, 1)`). Both
            // revisions ship on Strix-family silicon — a public
            // Framework 13 (AMD AI 300) boot log loads the 14.0.0 TOC.
            (14, 0, 0) => Some(("amdgpu/psp_14_0_0_toc.bin", true)),
            (14, 0, 1) => Some(("amdgpu/psp_14_0_1_toc.bin", true)),
            _ => None,
        }
    })
    .flatten();
    let (psp_name, is_toc) = stage_failed("psp-version", psp_image.ok_or(Error::Unsupported))?;
    let psp_image = if is_toc {
        PspImage::Toc(stage_failed(
            "psp-toc-open",
            fw_cap
                .invoke(OpenToc(psp_name))
                .map_err(|_| Error::Revoked)?,
        )?)
    } else {
        PspImage::Asd(stage_failed(
            "psp-asd-open",
            fw_cap
                .invoke(OpenAsd(psp_name))
                .map_err(|_| Error::Revoked)?,
        )?)
    };
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
        let mut loader = stage_failed("psp-loader", unsafe {
            match &psp_image {
                PspImage::Toc(toc) => Loader::new_psp(gpu, cap, &pool, &firmware, toc),
                PspImage::Asd(asd) => Loader::new_psp12(gpu, cap, &pool, &firmware, asd),
            }
        })?;
        graphics(gpu, &fw_cap, &mut loader);
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

/// Bring Raphael's graphics engines up on the display path's pool, once its
/// PSP session loaded the graphics set and the RLC autoload completed. A
/// failure is reported and leaves the display as it is; the owner is returned
/// either way, since an engine may still reach memory it published.
async fn graphics_boot(
    pool: &Pool,
    firmware: Option<crate::amdgpu_info_navi22::Firmware>,
) -> Option<crate::amdgpu_raphael_boot::ColdBoot> {
    use core::fmt::Write as _;
    // Strix is dispatched to `graphics_boot_strix`, not here: its owner
    // is the Strix Point ColdBoot (SMU 14.0.0, driver-IF 0x7 — the
    // 14.0.1/0x6 grounding in #2486 was Strix Halo, corrected by the
    // ColdBoot owner lane, #2467). Refuse by name instead of falling
    // through to the Raphael owner's profile check, whose error would
    // mislabel the chip. Display still comes up; only the graphics
    // engines stay down.
    let is_strix =
        crate::amdgpu::with_controller(|gpu| gpu.chip.family == crate::amdgpu::Family::Strix)
            .unwrap_or(false);
    if is_strix {
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: strix graphics refused: Raphael path does not serve Strix (see graphics_boot_strix)"
        );
        return None;
    }
    let authority = crate::amdgpu::pci_authority()?;
    let device = crate::amdgpu::pci_device()?;
    let boot = crate::amdgpu::with_controller(|gpu| {
        crate::amdgpu_info::sample_raphael_board(gpu, &authority, &device);
        // SAFETY: this display owner holds the whole GPU after the boot
        // handoff: no other graphics owner exists, the pool is its free
        // carve-out, and the PSP has loaded the graphics set. Construction
        // performs no register I/O.
        unsafe { crate::amdgpu_raphael_boot::ColdBoot::new(gpu, authority, pool, device) }
    })?;
    let mut boot = match boot {
        Ok(boot) => boot,
        Err(error) => {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: raphael graphics refused: {error:?}"
            );
            return None;
        }
    };
    // SAFETY: as above, and the RLC autoload has completed.
    unsafe { run_graphics(&mut boot, firmware) }.await;
    Some(boot)
}
/// Run `boot`'s stages, report them, and publish the loaded firmware's
/// versions after a completed run.
///
/// # Safety
/// `ColdBoot::run`'s: the owner is new or re-armed, this display owner holds
/// the whole GPU, and the RLC autoload has completed.
async unsafe fn run_graphics(
    boot: &mut crate::amdgpu_raphael_boot::ColdBoot,
    firmware: Option<crate::amdgpu_info_navi22::Firmware>,
) {
    use core::fmt::Write as _;
    // SAFETY: forwarded.
    match unsafe { boot.run() }.await {
        Ok(report) => {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: raphael graphics up: smu {:#x}, {} CUs, RB mask {:#x}",
                report.smu.smu,
                report.topology.active_cus,
                report.topology.enabled_rb_mask
            );
            // AMDGPU_INFO_FW_VERSION describes what loaded. The rings stay
            // unadvertised until a client submitter registers.
            if let Some(firmware) = firmware {
                crate::amdgpu_info::publish_navi22_boot(crate::amdgpu_info_navi22::Boot {
                    firmware,
                    smc: report.smu.smu,
                    gfx_mhz: None,
                    queues_verified: true,
                    sdma_rings: 1,
                });
            }
        }
        Err(error) => {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: raphael graphics failed: {error:?}"
            );
        }
    }
}
/// Build a Phoenix graphics owner without running it: construct the
/// coordinator (no register I/O) and box it.
///
/// `#[inline(never)]` is load-bearing for the frame budget: the
/// construction `Result` is 2464 bytes, and inlining this helper into
/// `graphics_boot_phoenix` would put that temporary back into the boot
/// future's poll frame. Kept out of line, the temporary lives in this
/// function's own frame (~2.6 KiB, well under budget) and the async
/// boot future holds only the box.
///
/// # Safety
/// This display owner holds the whole GPU after the boot handoff: no
/// other graphics owner exists, the pool is its free carve-out, and the
/// PSP has loaded the graphics set. Construction performs no register I/O.
#[inline(never)]
fn build_phoenix_boot(
    pool: &Pool,
    mes_start: [u64; 2],
) -> Option<alloc::boxed::Box<crate::amdgpu_phoenix_boot::PhoenixColdBoot>> {
    use core::fmt::Write as _;
    let authority = crate::amdgpu::pci_authority()?;
    let device = crate::amdgpu::pci_device()?;
    let boot = crate::amdgpu::with_controller(|gpu| {
        // SAFETY: as documented on this function.
        unsafe {
            crate::amdgpu_phoenix_boot::PhoenixColdBoot::new(
                gpu, authority, pool, &device, mes_start,
            )
        }
    })?;
    match boot {
        Ok(boot) => Some(alloc::boxed::Box::new(boot)),
        Err(error) => {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: phoenix graphics refused: {error:?}"
            );
            None
        }
    }
}
/// Bring Phoenix's graphics engines up on the display path's pool, once its
/// PSP session loaded the graphics set and the RLC autoload completed. A
/// failure is reported and leaves the display as it is; the owner is returned
/// either way, since an engine may still reach memory it published.
/// `mes_start` is the MES program-counter entry points (sched + KIQ) from
/// the loader; see `Loader::mes_start_addrs`.
async fn graphics_boot_phoenix(
    pool: &Pool,
    mes_start: [u64; 2],
) -> Option<alloc::boxed::Box<crate::amdgpu_phoenix_boot::PhoenixColdBoot>> {
    // Boxed: the owner is 2464 bytes and this future holds it across the
    // `run_graphics_phoenix` await; inline, the future carried the owner,
    // its construction `Result`, and the `Option` return slot by value,
    // and the start task's poll frame measured 9080 bytes against the
    // 8192 budget (run 45447920311). Built in `build_phoenix_boot`, the
    // future holds only the box (~1.5 KiB) and the frame is independent
    // of the owner's size.
    let mut boot = build_phoenix_boot(pool, mes_start)?;
    // SAFETY: the owner is new, this display owner holds the whole GPU,
    // and the RLC autoload has completed.
    unsafe { run_graphics_phoenix(&mut boot) }.await;
    Some(boot)
}
/// Run `boot`'s stages and report them.
///
/// # Safety
/// `PhoenixColdBoot::run`'s: the owner is new, this display owner holds the
/// whole GPU, and the RLC autoload has completed.
async unsafe fn run_graphics_phoenix(boot: &mut crate::amdgpu_phoenix_boot::PhoenixColdBoot) {
    use core::fmt::Write as _;
    // SAFETY: forwarded.
    match unsafe { boot.run() }.await {
        Ok(report) => {
            // The rings stay unadvertised until a client submitter registers.
            // No `amdgpu_info` publication yet: its boot struct is
            // Navi22/gfx10-typed, and Phoenix's topology is its own struct.
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: phoenix graphics up: smu {:#x}, {} CUs, RB mask {:#x}, mes {:#x}/{:#x}",
                report.smu.smu,
                report.topology.active_cus,
                report.topology.enabled_rb_mask,
                report.mes.sched_version,
                report.mes.kiq_version
            );
        }
        Err(error) => {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: phoenix graphics failed: {error:?}"
            );
        }
    }
}
/// Bring Strix's graphics engines up on the display path's pool, once its
/// PSP session loaded the graphics set and the RLC autoload completed. A
/// failure is reported and leaves the display as it is; the owner is returned
/// either way, since an engine may still reach memory it published.
/// `mes_start` is the MES program-counter entry points (sched + KIQ) from
/// the loader; see `Loader::mes_start_addrs`.
///
/// The DID dispatch is in `start`'s spawn task, checked before the Phoenix
/// branch: Strix is its own family (`Family::Strix`), so the Phoenix branch
/// must not claim it. All sixteen stages have owners now; `run` executes
/// them and this returns the owner either way.
async fn graphics_boot_strix(
    pool: &Pool,
    mes_start: [u64; 2],
) -> Option<crate::amdgpu_strix_boot::StrixColdBoot> {
    use core::fmt::Write as _;
    let authority = crate::amdgpu::pci_authority()?;
    let device = crate::amdgpu::pci_device()?;
    let boot = crate::amdgpu::with_controller(|gpu| {
        // SAFETY: this display owner holds the whole GPU after the boot
        // handoff: no other graphics owner exists, the pool is its free
        // carve-out, and the PSP has loaded the graphics set. Construction
        // performs no register I/O.
        unsafe {
            crate::amdgpu_strix_boot::StrixColdBoot::new(gpu, authority, pool, &device, mes_start)
        }
    })?;
    let mut boot = match boot {
        Ok(boot) => boot,
        Err(error) => {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: strix graphics refused: {error:?}"
            );
            return None;
        }
    };
    // SAFETY: as above, and the RLC autoload has completed.
    unsafe { run_graphics_strix(&mut boot) }.await;
    Some(boot)
}
/// Run `boot`'s stages and report them.
///
/// # Safety
/// `StrixColdBoot::run`'s: the owner is new, this display owner holds the
/// whole GPU, and the RLC autoload has completed.
async unsafe fn run_graphics_strix(boot: &mut crate::amdgpu_strix_boot::StrixColdBoot) {
    use core::fmt::Write as _;
    // SAFETY: forwarded.
    match unsafe { boot.run() }.await {
        Ok(report) => {
            // The rings stay unadvertised until a client submitter registers.
            // No `amdgpu_info` publication yet: its boot struct is
            // Navi22/gfx10-typed, and Strix's topology is its own struct.
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: strix graphics up: smu {:#x}, {} stages",
                report.smu.smu,
                report.stages_completed
            );
        }
        Err(error) => {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: strix graphics failed: {error:?}"
            );
        }
    }
}
/// VCN and JPEG on a completed Strix graphics boot. There is no VCN 4.0
/// owner yet, so this is a remainder no-op that says so; media is not one
/// of the cold boot's sixteen stages.
async fn media_boot_strix(graphics: &mut crate::amdgpu_strix_boot::StrixColdBoot) {
    use core::fmt::Write as _;
    if !graphics.queues_verified() {
        return;
    }
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: strix media: no VCN 4.0 owner yet; graphics only"
    );
}
/// VCN and JPEG on a completed Phoenix graphics boot. There is no VCN 4.0
/// owner yet, so this is a remainder no-op that says so; media is not one
/// of the cold boot's sixteen stages.
async fn media_boot_phoenix(graphics: &mut crate::amdgpu_phoenix_boot::PhoenixColdBoot) {
    use core::fmt::Write as _;
    if !graphics.queues_verified() {
        return;
    }
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: phoenix media: no VCN 4.0 owner yet; graphics only"
    );
}
/// VCN and JPEG on a completed Raphael graphics boot, through the PSP session
/// that loaded them. Failure is reported and leaves graphics and display be.
async fn media_boot(graphics: &mut crate::amdgpu_raphael_boot::ColdBoot, loader: &mut Loader) {
    use core::fmt::Write as _;
    if !matches!(
        graphics.state(),
        crate::amdgpu_raphael_boot::State::Ready(_)
    ) {
        return;
    }
    let Some((psp, firmware, vcn_bytes)) = loader.media() else {
        return;
    };
    // SAFETY: the display owner holds the whole GPU; graphics completed and
    // `psp` is the session that loaded the VCN image, still holding its TMR.
    match unsafe { graphics.run_media(psp, firmware, vcn_bytes) }.await {
        Ok(status) => {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: raphael media up: {:?}",
                status.state
            );
        }
        Err(error) => {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: raphael media failed: {error:?}"
            );
        }
    }
}
/// Completed mode 2 recoveries since boot (`amdgpu_ctx::recoveries` adds
/// them, so contexts from before a reset see their jobs cancelled).
static RECOVERIES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
pub(crate) fn recoveries() -> u64 {
    RECOVERIES.load(core::sync::atomic::Ordering::Acquire)
}
/// Linux's `amdgpu_gpu_recovery`: -1 (the default) recovers an APU like
/// Raphael; `amdgpu.gpu_recovery=0` turns it off.
pub(crate) fn gpu_recovery_enabled() -> bool {
    narf_boot::args().value("amdgpu.gpu_recovery") != Some("0")
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryError {
    /// No display owner with a completed graphics boot to recover.
    Busy,
    Quiesce(crate::amdgpu_raphael_boot::Error),
    QuiescePhoenix(crate::amdgpu_phoenix_boot::Error),
    Display(crate::amdgpu_dcn_display::Error),
    Psp(crate::amdgpu_dmub_boot::Error),
    Reset(crate::amdgpu_raphael_reset::Error),
    ResetPhoenix(crate::amdgpu_phoenix_boot::Error),
    /// The PSP session came back without the graphics set loaded.
    NoGraphics,
    /// The rebuilt graphics owner did not complete its boot.
    Graphics,
}
/// Raphael's `amdgpu_device_gpu_recover` with a mode 2 reset, for a hang no
/// ring-level rung recovered:
/// 1. Quiesce: the client path withdrawn (every job fails), the watchdog
///    stopped, the IH ring disabled, every fence wait abandoned, the stream
///    disabled.
/// 2. `psp_suspend`: DMUB stopped, the TMR released, the PSP ring stopped.
/// 3. The mode 2 reset (`nv_asic_mode2_reset`).
/// 4. Re-initialization, as `amdgpu_device_reinit_after_reset`:
///    - the PSP session booted again, which loads the graphics set and runs
///      the RLC autoload;
///    - DMUB notifications;
///    - the graphics coordinator re-armed and run again on its own
///      reservations, then media, then client registration.
///
///    Only a coordinator that cannot be re-armed is kept, quarantined, and
///    a new one built.
/// 5. The stream put back on the mode it was validated for (DM's resume).
///    The carve-out survives a mode 2 reset (`amdgpu_device_check_vram_lost`
///    reports no loss), so the scanout is not cleared.
///
/// A failure after the quiesce leaves graphics stopped. The display is
/// left as far as it got.
pub(crate) async fn recover() -> Result<(), RecoveryError> {
    use core::fmt::Write as _;
    let mut guard = DISPLAY.lock().await;
    let display = guard.as_mut().ok_or(RecoveryError::Busy)?;
    let device = crate::amdgpu::pci_device().ok_or(RecoveryError::Busy)?;
    if display.graphics_phoenix.is_some() {
        return recover_phoenix(display).await;
    }
    if !display
        .graphics
        .as_ref()
        .is_some_and(crate::amdgpu_raphael_boot::ColdBoot::queues_verified)
    {
        return Err(RecoveryError::Busy);
    }
    let _ = writeln!(narf_console::Writer, "amdgpu: raphael MODE2 reset");
    // 1. Quiesce.
    crate::amdgpu_navi22_cs::unregister();
    crate::amdgpu_navi22_tdr::stop();
    let Display {
        loader,
        pool,
        stream,
        graphics,
        retired,
        ..
    } = display;
    let old = graphics.as_mut().ok_or(RecoveryError::Busy)?;
    // amdgpu_device_ip_suspend's UNGATE: GFX powered for what follows.
    if let Err(error) = old.ungate_gfx().await {
        let _ = writeln!(narf_console::Writer, "amdgpu: raphael GFX ungate {error:?}");
    }
    // SAFETY: the client path is withdrawn; `old` is re-armed below.
    unsafe { old.quiesce_for_reset() }
        .await
        .map_err(RecoveryError::Quiesce)?;
    crate::amdgpu_fence_navi22::abandon_all();
    if let Some(running) = stream.as_mut() {
        running
            .pipeline
            .disable(loader)
            .await
            .map_err(RecoveryError::Display)?;
    }
    // 2-3. psp_suspend, then the reset of everything that ran from the TMR.
    // SAFETY: the mode 2 reset follows at once, and the loader boots again
    // before the display or graphics are used.
    unsafe { loader.stop_for_reset() }
        .await
        .map_err(RecoveryError::Psp)?;
    // SAFETY: quiesced above, TMR released; everything is rebuilt below.
    unsafe { old.mode2_reset(&device) }
        .await
        .map_err(RecoveryError::Reset)?;
    // 4. Re-initialization.
    loader
        .boot(Default::default())
        .await
        .map_err(RecoveryError::Psp)?;
    loader
        .enable_notifications()
        .await
        .map_err(RecoveryError::Psp)?;
    // Contexts from before the reset see it (amdgpu_ctx::recoveries).
    rebuild_graphics(loader, pool, graphics, retired, true).await?;
    // 5. The stream, as `resume` puts it back.
    if let Some(running) = stream.as_mut() {
        running
            .pipeline
            .start()
            .await
            .map_err(RecoveryError::Display)?;
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
            .map_err(RecoveryError::Display)?;
    }
    Ok(())
}
/// After the PSP session loaded the graphics set again (a recovery, or the
/// display's S3 resume): bring graphics up again, then media and client
/// registration. The spent coordinator is re-armed and run on its own
/// reservations, as Linux's hw_init reuses its buffers. Only if it cannot be
/// re-armed is it retired, quarantined, and a new one built. `reset` moves
/// the recovery counter first, so contexts from before see their work
/// cancelled; an S3 resume keeps them (Linux drains the rings before
/// suspending, and the carve-out survives).
async fn rebuild_graphics(
    loader: &mut Loader,
    pool: &Pool,
    graphics: &mut Option<crate::amdgpu_raphael_boot::ColdBoot>,
    retired: &mut Vec<crate::amdgpu_raphael_boot::ColdBoot>,
    reset: bool,
) -> Result<(), RecoveryError> {
    use core::fmt::Write as _;
    if !loader.graphics_booted() {
        return Err(RecoveryError::NoGraphics);
    }
    if reset {
        // Contexts are told of the reset; media starts with no sessions.
        if let Some(old) = graphics.as_mut() {
            old.forget_media_sessions();
        }
    }
    let firmware = loader.graphics_versions();
    let rearmed = match graphics.as_mut() {
        // SAFETY: the device was reset (mode 2 or S3) since the coordinator
        // last ran, it was quiesced, and the PSP has reloaded the set.
        Some(old) => match unsafe { old.rearm() }.await {
            Ok(()) => true,
            Err(error) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: raphael graphics not re-armed ({error:?}); a new owner"
                );
                false
            }
        },
        None => false,
    };
    if rearmed {
        let boot = graphics.as_mut().ok_or(RecoveryError::Graphics)?;
        // SAFETY: re-armed above; this display owner holds the GPU.
        alloc::boxed::Box::pin(unsafe { run_graphics(boot, firmware) }).await;
    } else {
        if let Some(old) = graphics.take() {
            retired.push(old);
        }
        *graphics = alloc::boxed::Box::pin(graphics_boot(pool, firmware)).await;
    }
    let new = graphics
        .as_mut()
        .filter(|g| g.queues_verified())
        .ok_or(RecoveryError::Graphics)?;
    alloc::boxed::Box::pin(media_boot(new, loader)).await;
    if reset {
        RECOVERIES.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    }
    serve_clients(new);
    gate_graphics(new).await;
    // A rebuild that could not re-arm quarantined the old owners; say what
    // is left.
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: raphael graphics {} ({} retired owners, {} MiB of the carve-out free)",
        if rearmed { "re-armed" } else { "rebuilt" },
        retired.len(),
        pool.available() >> 20
    );
    Ok(())
}
/// Phoenix's `amdgpu_device_gpu_recover` with a mode 2 reset, mirroring
/// [`recover`] but rebuild-only: the Phoenix coordinator has no `rearm`
/// (the rings' host write pointers live in contexts with no reset API), so
/// the spent coordinator is always retired, quarantined, and a new one built.
/// No client path exists yet (no submitter), so there is nothing to
/// withdraw or re-register beyond the IH disable and fence abandonment.
/// Unlike Raphael's reset, the Phoenix PMFW message needs no device.
async fn recover_phoenix(display: &mut Display) -> Result<(), RecoveryError> {
    use core::fmt::Write as _;
    if !display
        .graphics_phoenix
        .as_ref()
        .is_some_and(|boot| boot.queues_verified())
    {
        return Err(RecoveryError::Busy);
    }
    let _ = writeln!(narf_console::Writer, "amdgpu: phoenix MODE2 reset");
    // 1. Quiesce.
    crate::amdgpu_navi22_tdr::stop();
    let Display {
        loader,
        pool,
        stream,
        graphics_phoenix,
        retired_phoenix,
        ..
    } = display;
    let old = graphics_phoenix.as_mut().ok_or(RecoveryError::Busy)?;
    // amdgpu_device_ip_suspend's UNGATE: GFX powered for what follows.
    if let Err(error) = old.ungate_gfx().await {
        let _ = writeln!(narf_console::Writer, "amdgpu: phoenix GFX ungate {error:?}");
    }
    // SAFETY: no client path exists yet; `old` is retired below.
    old.quiesce_for_reset()
        .await
        .map_err(RecoveryError::QuiescePhoenix)?;
    crate::amdgpu_fence_navi22::abandon_all();
    if let Some(running) = stream.as_mut() {
        running
            .pipeline
            .disable(loader)
            .await
            .map_err(RecoveryError::Display)?;
    }
    // 2-3. psp_suspend, then the reset of everything that ran from the TMR.
    // SAFETY: the mode 2 reset follows at once, and the loader boots again
    // before the display or graphics are used.
    unsafe { loader.stop_for_reset() }
        .await
        .map_err(RecoveryError::Psp)?;
    // SAFETY: quiesced above, TMR released; everything is rebuilt below.
    // The scratch3 save/restore + memsize wrapper is a flagged remainder
    // (needs the Phoenix NBIO 7.4 banks).
    old.mode2_reset()
        .await
        .map_err(RecoveryError::ResetPhoenix)?;
    // 4. Re-initialization.
    loader
        .boot(Default::default())
        .await
        .map_err(RecoveryError::Psp)?;
    loader
        .enable_notifications()
        .await
        .map_err(RecoveryError::Psp)?;
    // Contexts from before the reset see it (amdgpu_ctx::recoveries).
    rebuild_graphics_phoenix(loader, pool, graphics_phoenix, retired_phoenix).await?;
    // 5. The stream, as `resume` puts it back.
    if let Some(running) = stream.as_mut() {
        running
            .pipeline
            .start()
            .await
            .map_err(RecoveryError::Display)?;
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
            .map_err(RecoveryError::Display)?;
    }
    Ok(())
}
/// After the PSP session loaded the graphics set again: build a new Phoenix
/// coordinator (rebuild-only, no re-arm), then media and client registration.
/// The spent coordinator is retired, quarantined, and a new one built.
async fn rebuild_graphics_phoenix(
    loader: &mut Loader,
    pool: &Pool,
    graphics: &mut Option<alloc::boxed::Box<crate::amdgpu_phoenix_boot::PhoenixColdBoot>>,
    retired: &mut Vec<crate::amdgpu_phoenix_boot::PhoenixColdBoot>,
) -> Result<(), RecoveryError> {
    use core::fmt::Write as _;
    if !loader.graphics_booted() {
        return Err(RecoveryError::NoGraphics);
    }
    let Some(mes_start) = loader.mes_start_addrs() else {
        return Err(RecoveryError::NoGraphics);
    };
    if let Some(old) = graphics.take() {
        retired.push(*old);
    }
    *graphics = alloc::boxed::Box::pin(graphics_boot_phoenix(pool, mes_start)).await;
    let new = graphics
        .as_mut()
        .filter(|g| g.queues_verified())
        .ok_or(RecoveryError::Graphics)?;
    alloc::boxed::Box::pin(media_boot_phoenix(new)).await;
    RECOVERIES.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    serve_clients_phoenix(new);
    gate_graphics_phoenix(new).await;
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: phoenix graphics rebuilt ({} retired owners, {} MiB of the carve-out free)",
        retired.len(),
        pool.available() >> 20
    );
    Ok(())
}

/// Raphael's graphics across S3 (`amdgpu_device_suspend` /
/// `amdgpu_device_resume` with graphics up), split between the system-PM
/// phases:
/// 1. Async prepare: the rings drained, the client path withdrawn, the IH
///    ring disabled, every fence wait abandoned.
/// 2. Sync suspend: the stream disabled, and the PSP `psp_suspend` (TMR and
///    ring) with graphics quiesced. S3 powers the engines off, which is the
///    reset that release needs.
/// 3. Sync resume: the PSP session booted again (the graphics set reloaded,
///    the RLC autoload run), then the stream replayed.
/// 4. Async resume: a new coordinator, then media and clients. A suspend
///    that aborted before the PSP stopped never powered the GPU off, so
///    that resume runs a mode 2 reset first.
///
/// Suspend-to-idle takes none of this: see [`GraphicsPm::Idle`]. Hibernation
/// takes all of it, with the carve-out emptied first and a reset after the
/// PSP stops: see [`prepare_graphics_hibernate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GraphicsPm {
    Running,
    /// Prepared for suspend: client path withdrawn, IH disabled.
    Quiesced,
    /// The PSP released the TMR for S3.
    Stopped,
    /// Suspend-to-idle without s0ix: graphics and the display are left
    /// running through the park, and the PSP keeps its TMR, as Linux's
    /// amdgpu does when `amdgpu_acpi_is_s0ix_active` is false.
    Idle,
    /// Prepared for hibernation: as `Quiesced`, with every unpinned client
    /// buffer moved out of the carve-out.
    Freezing,
    /// Frozen for hibernation: the TMR released and the GPU reset (mode 2),
    /// as `amdgpu_pmops_freeze` leaves an APU while the image is written.
    Frozen,
    /// Suspend-to-idle on Linux's s0ix path: clients paused, the rings
    /// drained, media suspended. The sync suspend then blanks the stream and
    /// halts the RLC, IH, MMHUB and the doorbells. GFX, SDMA and the PSP are
    /// never suspended, and all of it resumes in place.
    S0ix,
}
/// Why Raphael would not take Linux's s0ix path for a suspend-to-idle
/// (`amdgpu_acpi_is_s0ix_active` for an APU, in its order).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum S0ix {
    Active,
    /// `amdgpu.ppfeaturemask` has no `PP_GFXOFF_MASK`.
    NoGfxoff,
    /// The FADT lacks `LOW_POWER_S0`: "BIOS has not been configured for
    /// suspend-to-idle".
    NoLowPowerS0,
    /// No AMD PMC driver takes the SoC into S0i3 (Linux without
    /// `CONFIG_AMD_PMC`).
    NoPmc,
}
/// Whether the AMD PMC driver bound (Linux's `CONFIG_AMD_PMC`): it sends the
/// SoC its S0i3 OS hint through the LPS0 handler list (`drivers/platform`'s
/// `amd_pmc`).
fn amd_pmc() -> bool {
    narf_power::lps0::has_handler("amd_pmc")
}
pub(crate) fn s0ix(gfxoff: bool, low_power_s0: bool, pmc: bool) -> S0ix {
    if !gfxoff {
        S0ix::NoGfxoff
    } else if !low_power_s0 {
        S0ix::NoLowPowerS0
    } else if !pmc {
        S0ix::NoPmc
    } else {
        S0ix::Active
    }
}
/// What the async resume must do from the state suspend left.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResumeWork {
    Nothing,
    /// The sync resume reloaded the graphics set: build a new coordinator.
    Rebuild,
    /// The GPU never lost power: reset it (mode 2), then rebuild.
    ResetThenRebuild,
    /// An s0ix cycle: the sync resume brought the engines back in place.
    /// Media restarts with its sessions and the clients are served again.
    InPlace,
}
pub(crate) fn resume_work(state: GraphicsPm) -> ResumeWork {
    match state {
        GraphicsPm::Running | GraphicsPm::Idle => ResumeWork::Nothing,
        // A restored image finds the GPU power-cycled, a failed image write
        // finds it reset: the sync resume booted the PSP either way.
        GraphicsPm::Stopped | GraphicsPm::Frozen => ResumeWork::Rebuild,
        GraphicsPm::Quiesced | GraphicsPm::Freezing => ResumeWork::ResetThenRebuild,
        GraphicsPm::S0ix => ResumeWork::InPlace,
    }
}
/// Where the sync suspend leaves graphics once the PSP stop has run, and
/// whether the suspend may go on. S3's power-off is the reset releasing the
/// TMR needs; a hibernation writes its image first, so it resets now, as
/// `amdgpu_pmops_freeze` does (`amdgpu_acpi_should_gpu_reset`). `reset` runs
/// only then. A failed reset fails the freeze, as Linux's does.
pub(crate) fn after_psp_stop(
    state: GraphicsPm,
    stopped: bool,
    reset: impl FnOnce() -> bool,
) -> (GraphicsPm, bool) {
    match state {
        _ if !stopped => (state, false),
        GraphicsPm::Freezing if reset() => (GraphicsPm::Frozen, true),
        GraphicsPm::Freezing => (GraphicsPm::Stopped, false),
        _ => (GraphicsPm::Stopped, true),
    }
}
/// How long the prepare hook waits for submitted jobs (the GFX job timeout,
/// as Navi22's suspend drain).
const RING_DRAIN_MS: u64 = 10_000; // linux: n/a (NARF policy, amdgpu_fence_wait_empty bound)
/// Whether every kernel queue's and media ring's submitted jobs completed
/// within `ms` (`amdgpu_fence_driver_hw_fini` waits on every ring).
async fn rings_idle(ms: u64) -> bool {
    let deadline = narf_time::Deadline::after_ms(ms);
    loop {
        let queues = match crate::amdgpu_rdna2_client::queue_progress().await {
            Ok(samples) => samples
                .iter()
                .all(|p| crate::amdgpu_fence_navi22::signaled(p.signaled, p.emitted)),
            Err(_) => return false,
        };
        let media = {
            let mut owner = graphics_owner().await;
            match owner.get().map(|boot| boot.media_signalled()) {
                Some(Ok(done)) => done,
                Some(Err(_)) => return false,
                None => true,
            }
        };
        if queues && media {
            return true;
        }
        if deadline.expired() {
            return false;
        }
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
    }
}
/// Suspend-to-idle with graphics up. Linux's amdgpu suspends an APU for
/// s2idle only on its s0ix path, which needs the SoC to reach S0i3 (it
/// halts the RLC and relies on GFXOFF exit to restart it). Without that,
/// `amdgpu_pmops_prepare` and `_suspend` leave the device alone. NARF has
/// no AMD PMC driver, so that is always the case here: the device is marked
/// [`GraphicsPm::Idle`] and nothing else changes. The S3 sequence is no
/// substitute: it releases the TMR under GFX, which is sound only because
/// S3 then cuts power.
async fn prepare_graphics_idle() {
    use core::fmt::Write as _;
    if crate::amdgpu_rdna2_client::backend() != crate::amdgpu_rdna2_client::Backend::Raphael {
        return;
    }
    let gfxoff = crate::amdgpu_rdna2::options::BootOptions::parse(narf_boot::args().raw()).gfxoff;
    let low_power_s0 = narf_acpi::fadt_pm().is_some_and(|fadt| fadt.low_power_s0);
    let why = s0ix(gfxoff, low_power_s0, amd_pmc());
    if why == S0ix::Active {
        prepare_graphics_s0ix().await;
        return;
    }
    let mut guard = DISPLAY.lock().await;
    let Some(display) = guard.as_mut() else {
        return;
    };
    if !display
        .graphics
        .as_ref()
        .is_some_and(|g| g.queues_verified())
    {
        return;
    }
    display.graphics_pm = GraphicsPm::Idle;
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: raphael s2idle without s0ix ({why:?}): graphics and display stay up"
    );
}
/// The async half of Linux's s0ix suspend (`amdgpu_device_suspend` with
/// `in_s0ix`):
/// - `amdgpu_fence_driver_hw_fini`'s wait for the rings;
/// - the client path paused with its VMIDs and media sessions kept;
/// - `vcn_v3_0_suspend`, with each VCPU saved.
///
/// No PG/CG is ungated: Linux skips GFX and SDMA there. The sync suspend
/// does the rest (`GraphicsPm::S0ix`).
async fn prepare_graphics_s0ix() {
    use core::fmt::Write as _;
    {
        // amdgpu_device_prepare: a scheduled GFXOFF allow is delivered now,
        // so GFX is off before the park instead of 100 ms into it.
        let mut owner = graphics_owner().await;
        if let Some(boot) = owner.get() {
            if let Err(error) = boot.flush_gfx_off().await {
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: raphael GFXOFF flush {error:?}"
                );
            }
        }
    }
    drain_rings().await;
    let mut guard = DISPLAY.lock().await;
    let Some(display) = guard.as_mut() else {
        return;
    };
    let Some(graphics) = display.graphics.as_mut().filter(|g| g.queues_verified()) else {
        return;
    };
    crate::amdgpu_navi22_cs::pause();
    crate::amdgpu_navi22_tdr::stop();
    if let Err(error) = graphics.suspend_media().await {
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: raphael media sessions not saved: {error:?}"
        );
    }
    display.graphics_pm = GraphicsPm::S0ix;
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: raphael s2idle on the s0ix path"
    );
}
async fn prepare_graphics_suspend() {
    if crate::amdgpu_rdna2_client::backend() != crate::amdgpu_rdna2_client::Backend::Raphael {
        return;
    }
    // amdgpu_fence_driver_hw_fini waits for the rings to empty first.
    drain_rings().await;
    quiesce_graphics(GraphicsPm::Quiesced, Vec::new()).await;
}
async fn drain_rings() {
    use core::fmt::Write as _;
    if !rings_idle(RING_DRAIN_MS).await {
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: raphael rings still busy at suspend; their jobs fail"
        );
    }
}
/// Hibernation with graphics up (`amdgpu_pmops_freeze` on an APU): the S3
/// preparation, with the carve-out emptied first. S4 loses it, and an APU's
/// VRAM is evicted only for S4 (`amdgpu_device_evict_resources`), so every
/// unpinned client buffer moves to system memory, which the image captures.
/// Pinned ones (a scanned-out framebuffer) stay and lose their contents, as
/// in Linux. Kernel state needs nothing: the rings, MQDs, GART table and
/// scanout are rebuilt or cleared at resume, firmware is staged again from
/// system memory, and VCN's buffer is saved as for S3. The sync suspend then
/// resets the GPU after the PSP stops ([`after_psp_stop`]).
///
/// Placement is excluded first, in clients' order (before the display
/// owner), and held until the client path is withdrawn, so no submission or
/// placement lands in the carve-out after its buffers left. A failed
/// eviction puts the heap back and refuses the hibernation with graphics
/// still running.
async fn prepare_graphics_hibernate() -> Result<(), narf_power::device_pm::DevicePmError> {
    use core::fmt::Write as _;
    if crate::amdgpu_rdna2_client::backend() != crate::amdgpu_rdna2_client::Backend::Raphael {
        return Ok(());
    }
    let Some(card) = crate::amdgpu_navi22_cs::drm_card() else {
        drain_rings().await;
        quiesce_graphics(GraphicsPm::Freezing, Vec::new()).await;
        return Ok(());
    };
    let gate = crate::amdgpu_gem::lock_placement_live(card)
        .await
        .map_err(|_| narf_power::device_pm::DevicePmError::Busy)?;
    drain_rings().await;
    let heap = crate::amdgpu_navi22_cs::client_heap();
    let evicted = match evict_for_hibernation(&gate, heap).await {
        Ok(evicted) => evicted,
        Err(error) => {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: raphael hibernation refused: client VRAM not evicted ({error:?})"
            );
            return Err(narf_power::device_pm::DevicePmError::Busy);
        }
    };
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: raphael hibernation: {} client buffers out of the carve-out",
        evicted.len()
    );
    quiesce_graphics(GraphicsPm::Freezing, evicted).await;
    drop(gate);
    Ok(())
}
/// `amdgpu_ttm_evict_resources(TTM_PL_VRAM)` for `gate`'s card: the heap is
/// withdrawn, so nothing new lands in it, then every unpinned buffer moves to
/// system memory with its bytes. Returns the buffers whose allowed domains
/// the move widened, for [`crate::amdgpu_gem::restore_domains`] at resume.
/// On failure their domains are put back and `heap` registered again.
pub(crate) async fn evict_for_hibernation(
    gate: &crate::amdgpu_gem::PlacementGuard,
    heap: Option<crate::amdgpu_gem::VramHeap>,
) -> Result<Vec<(Arc<crate::amdgpu_gem::GemObject>, u64)>, narf_filesystem::FsError> {
    let card = gate.card();
    crate::amdgpu_gem::unregister_vram_heap(card);
    let (touched, evicted) = crate::amdgpu_gem::evict_all(gate).await;
    match evicted {
        Ok(()) => Ok(touched),
        Err(error) => {
            crate::amdgpu_gem::restore_domains(touched);
            if let Some(heap) = heap {
                crate::amdgpu_gem::register_vram_heap(card, heap);
            }
            Err(error)
        }
    }
}
/// The S3 preparation from the drained rings on, leaving `next`. `evicted`
/// is kept for the resume; with no running graphics to quiesce it is put
/// back now.
async fn quiesce_graphics(
    next: GraphicsPm,
    evicted: Vec<(Arc<crate::amdgpu_gem::GemObject>, u64)>,
) {
    use core::fmt::Write as _;
    let mut guard = DISPLAY.lock().await;
    let display = guard
        .as_mut()
        .filter(|d| d.graphics.as_ref().is_some_and(|g| g.queues_verified()));
    let Some(display) = display else {
        crate::amdgpu_gem::restore_domains(evicted);
        return;
    };
    display.evicted = evicted;
    let Some(graphics) = display.graphics.as_mut() else {
        return;
    };
    // The media session table stays for the restored firmware context.
    crate::amdgpu_navi22_cs::suspend();
    crate::amdgpu_navi22_tdr::stop();
    // amdgpu_device_ip_suspend_phase1's UNGATE: GFX powered for the rest.
    if let Err(error) = graphics.ungate_gfx().await {
        let _ = writeln!(narf_console::Writer, "amdgpu: raphael GFX ungate {error:?}");
    }
    // vcn_v3_0_suspend: stopped, with each VCPU BO saved. A failure leaves
    // the resume to start media with no sessions.
    if let Err(error) = graphics.suspend_media().await {
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: raphael media sessions not saved: {error:?}"
        );
    }
    // SAFETY: the client path is withdrawn; the coordinator is re-armed at
    // resume.
    if let Err(error) = unsafe { graphics.quiesce_for_reset() }.await {
        let _ = writeln!(narf_console::Writer, "amdgpu: raphael IH quiesce {error:?}");
    }
    crate::amdgpu_fence_navi22::abandon_all();
    display.graphics_pm = next;
}
async fn resume_graphics() {
    use core::fmt::Write as _;
    let mut guard = DISPLAY.lock().await;
    let Some(display) = guard.as_mut() else {
        return;
    };
    let work = resume_work(display.graphics_pm);
    if work == ResumeWork::Nothing {
        // A suspend-to-idle left everything running.
        display.graphics_pm = GraphicsPm::Running;
        return;
    }
    if work == ResumeWork::InPlace {
        // amdgpu_device_ip_resume_phase2 with in_s0ix: media restarts with
        // its saved sessions (GFX, SDMA and the PSP were never suspended),
        // then the clients are served again on their kept VMIDs.
        display.graphics_pm = GraphicsPm::Running;
        let Display {
            loader, graphics, ..
        } = display;
        if let Some(graphics) = graphics.as_mut() {
            // SAFETY: the s0ix prepare stopped media; nothing has run on it.
            unsafe { graphics.media_after_s0ix() };
            alloc::boxed::Box::pin(media_boot(graphics, loader)).await;
            crate::amdgpu_navi22_cs::register_raphael(graphics);
            if let Err(error) = graphics.gate_after_s0ix().await {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: raphael s0ix gating {error:?}"
                );
            }
        }
        return;
    }
    let Display {
        loader,
        pool,
        graphics,
        retired,
        graphics_pm,
        evicted,
        ..
    } = display;
    let result = async {
        if work == ResumeWork::ResetThenRebuild {
            let device = crate::amdgpu::pci_device().ok_or(RecoveryError::Busy)?;
            let old = graphics.as_mut().ok_or(RecoveryError::Busy)?;
            // SAFETY: quiesced at prepare; the reset follows the TMR release
            // at once and everything is rebuilt below.
            unsafe { loader.stop_for_reset() }
                .await
                .map_err(RecoveryError::Psp)?;
            // SAFETY: as above; the TMR is released and graphics quiesced.
            unsafe { old.mode2_reset(&device) }
                .await
                .map_err(RecoveryError::Reset)?;
            loader
                .boot(Default::default())
                .await
                .map_err(RecoveryError::Psp)?;
            loader
                .enable_notifications()
                .await
                .map_err(RecoveryError::Psp)?;
        }
        rebuild_graphics(loader, pool, graphics, retired, false).await
    }
    .await;
    *graphics_pm = GraphicsPm::Running;
    // After a hibernation: back to their own domains, in system memory until
    // validation brings each into the heap the rebuild registered again.
    crate::amdgpu_gem::restore_domains(core::mem::take(evicted));
    if let Err(error) = result {
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: raphael graphics not resumed: {error:?}; display only"
        );
    }
}
/// The async system-PM phase for Raphael's graphics; registered once its
/// clients are served.
struct GraphicsSystemPm;
impl narf_power::system_pm::AsyncSystemPm for GraphicsSystemPm {
    fn prepare_suspend<'a>(&'a self) -> narf_power::system_pm::SystemPmFuture<'a> {
        alloc::boxed::Box::pin(async {
            prepare_graphics_suspend().await;
            Ok::<(), narf_power::device_pm::DevicePmError>(())
        })
    }
    fn prepare_suspend_target<'a>(
        &'a self,
        target: narf_power::system_pm::SystemSleepState,
    ) -> narf_power::system_pm::SystemPmFuture<'a> {
        use narf_power::system_pm::SystemSleepState;
        alloc::boxed::Box::pin(async move {
            match target {
                SystemSleepState::S3 => prepare_graphics_suspend().await,
                SystemSleepState::S0Idle => prepare_graphics_idle().await,
                SystemSleepState::S4 => prepare_graphics_hibernate().await?,
            }
            Ok::<(), narf_power::device_pm::DevicePmError>(())
        })
    }
    fn resume_from_suspend<'a>(&'a self) -> narf_power::system_pm::SystemPmFuture<'a> {
        alloc::boxed::Box::pin(async {
            // Retained: a cancelled resume still finishes the rebuild rather
            // than leave the coordinator half-built.
            crate::suspend_transition::Retained::new(
                async {
                    resume_graphics().await;
                    Ok::<(), narf_power::device_pm::DevicePmError>(())
                },
                alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false)),
                |cleanup| {
                    narf_scheduler::spawn(cleanup);
                },
            )
            .await
        })
    }
}

/// Publish a completed Raphael graphics boot to clients: its submitter,
/// VMIDs and heap, then `ACCEL_WORKING`. `graphics` loaded the set only with
/// `amdgpu.rdna2_accel` on, the switch the discrete boot turns this on with.
/// `amdgpu_device_ip_late_init`'s `set_pg_state(GATE)` for GFX, once clients
/// are served: power gating on and GFXOFF allowed after its delay. Failure is
/// reported; graphics stays up with GFX powered.
async fn gate_graphics(graphics: &mut crate::amdgpu_raphael_boot::ColdBoot) {
    use core::fmt::Write as _;
    if !graphics.queues_verified() {
        return;
    }
    if let Err(error) = graphics.gate_gfx().await {
        let _ = writeln!(narf_console::Writer, "amdgpu: raphael GFX gate {error:?}");
    }
}
/// `amdgpu_device_ip_late_init`'s `set_pg_state(GATE)` for Phoenix GFX,
/// once clients are served: power gating on and GFXOFF allowed after its
/// delay. There is no clock-gating owner yet, so the clocks stay ungated.
/// Failure is reported; graphics stays up with GFX powered.
async fn gate_graphics_phoenix(graphics: &mut crate::amdgpu_phoenix_boot::PhoenixColdBoot) {
    use core::fmt::Write as _;
    if !graphics.queues_verified() {
        return;
    }
    if let Err(error) = graphics.gate_gfx().await {
        let _ = writeln!(narf_console::Writer, "amdgpu: phoenix GFX gate {error:?}");
    }
}
/// `amdgpu_device_ip_late_init`'s `set_pg_state(GATE)` for Strix GFX,
/// once clients are served: power gating on and GFXOFF allowed after its
/// delay. There is no clock-gating owner yet, so the clocks stay ungated.
/// Failure is reported; graphics stays up with GFX powered.
async fn gate_graphics_strix(graphics: &mut crate::amdgpu_strix_boot::StrixColdBoot) {
    use core::fmt::Write as _;
    if !graphics.queues_verified() {
        return;
    }
    if let Err(error) = graphics.gate_gfx().await {
        let _ = writeln!(narf_console::Writer, "amdgpu: strix GFX gate {error:?}");
    }
}
/// `gfx_off_delay_work`: deliver `allow` [`DELAY_MS`] from now to the
/// coordinator that scheduled it. A disable request in between, or a newer
/// coordinator lifetime, makes it a no-op.
///
/// [`DELAY_MS`]: crate::amdgpu_raphael_gfxoff::DELAY_MS
pub(crate) fn schedule_gfx_off(allow: crate::amdgpu_raphael_gfxoff::Allow) {
    narf_scheduler::spawn(async move {
        use core::fmt::Write as _;
        let delay = crate::amdgpu_raphael_gfxoff::DELAY_MS;
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(delay).as_instant()).await;
        let mut owner = graphics_owner().await;
        if let Some(boot) = owner.get() {
            if let Err(error) = boot.delayed_gfx_off(allow).await {
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: raphael GFXOFF allow {error:?}"
                );
            }
        }
    });
}
fn serve_clients(graphics: &mut crate::amdgpu_raphael_boot::ColdBoot) {
    if !graphics.queues_verified() {
        return;
    }
    crate::amdgpu_navi22_cs::register_raphael(graphics);
    if crate::amdgpu_navi22_cs::drm_card()
        .and_then(crate::amdgpu_cs::submitter)
        .is_some()
    {
        crate::amdgpu_info_navi22::set_accel(true);
    }
    // S3 with graphics up (`GraphicsPm`). Replaced by name on a rebuild.
    narf_power::system_pm::register_async_system_pm(
        "amdgpu-raphael-graphics",
        alloc::sync::Arc::new(GraphicsSystemPm),
    );
}
/// Publish a completed Phoenix graphics boot to clients: there is no client
/// submitter yet (the RDNA3 submitter lane owns it), so nothing is
/// registered and `ACCEL` is not set — the rings stay unadvertised until a
/// submitter registers. No `GraphicsSystemPm` is registered either: no S3 /
/// s0ix path exists for Phoenix yet.
fn serve_clients_phoenix(graphics: &mut crate::amdgpu_phoenix_boot::PhoenixColdBoot) {
    use core::fmt::Write as _;
    if !graphics.queues_verified() {
        return;
    }
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: phoenix graphics up but no client submitter yet; ACCEL not set"
    );
}
/// Publish a completed Strix graphics boot to clients: there is no client
/// submitter yet, so nothing is registered and `ACCEL` is not set — the
/// rings stay unadvertised until a submitter registers. No
/// `GraphicsSystemPm` is registered either: no S3 / s0ix path exists for
/// Strix yet.
fn serve_clients_strix(graphics: &mut crate::amdgpu_strix_boot::StrixColdBoot) {
    use core::fmt::Write as _;
    if !graphics.queues_verified() {
        return;
    }
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: strix graphics up but no client submitter yet; ACCEL not set"
    );
}
/// `gfx_off_delay_work` for a Phoenix coordinator: deliver `allow`
/// [`DELAY_MS`] from now. A disable request in between, or a newer
/// coordinator lifetime, makes it a no-op.
///
/// [`DELAY_MS`]: crate::amdgpu_raphael_gfxoff::DELAY_MS
pub(crate) fn schedule_gfx_off_phoenix(allow: crate::amdgpu_raphael_gfxoff::Allow) {
    narf_scheduler::spawn(async move {
        use core::fmt::Write as _;
        let delay = crate::amdgpu_raphael_gfxoff::DELAY_MS;
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(delay).as_instant()).await;
        let mut owner = graphics_owner().await;
        if let Some(boot) = owner.get_phoenix() {
            if let Err(error) = boot.delayed_gfx_off(allow).await {
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: phoenix GFXOFF allow {error:?}"
                );
            }
        }
    });
}
/// `gfx_off_delay_work` for a Strix coordinator: deliver `allow`
/// [`DELAY_MS`] from now. A disable request in between, or a newer
/// coordinator lifetime, makes it a no-op.
///
/// [`DELAY_MS`]: crate::amdgpu_raphael_gfxoff::DELAY_MS
pub(crate) fn schedule_gfx_off_strix(allow: crate::amdgpu_raphael_gfxoff::Allow) {
    narf_scheduler::spawn(async move {
        use core::fmt::Write as _;
        let delay = crate::amdgpu_raphael_gfxoff::DELAY_MS;
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(delay).as_instant()).await;
        let mut owner = graphics_owner().await;
        if let Some(boot) = owner.get_strix() {
            if let Err(error) = boot.delayed_gfx_off(allow).await {
                let _ = writeln!(narf_console::Writer, "amdgpu: strix GFXOFF allow {error:?}");
            }
        }
    });
}
/// On an APU with a graphics ColdBoot (Raphael, Rembrandt), hand the loader
/// the graphics set so its PSP session loads every non-PSP firmware in Linux's
/// order (`psp_load_non_psp_fw`) and starts the RLC autoload, instead of DMCUB
/// alone; the ColdBoot then brings the engines up. `amdgpu.rdna2_accel=0` keeps
/// the display-only load. A set that cannot be opened or does not match the
/// DMCUB the loader validated leaves the display path as it was, and says why.
fn graphics(
    gpu: &AmdGpu,
    fw_cap: &Cap<narf_firmware::FirmwareRegistry, Read>,
    loader: &mut Loader,
) {
    use core::fmt::Write as _;
    let is_phoenix = crate::amdgpu::family_for_pci_id(gpu.chip.vid, gpu.chip.did)
        == Some(crate::amdgpu::Family::Phoenix);
    if !is_phoenix && crate::amdgpu_rdna2::apu_for_pci_id(gpu.chip.vid, gpu.chip.did).is_none() {
        return;
    }
    if !crate::amdgpu_rdna2::options::BootOptions::parse(narf_boot::args().raw()).accel {
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: graphics firmware not loaded (amdgpu.rdna2_accel=0)"
        );
        return;
    }
    if is_phoenix {
        // No Phoenix firmware-set opener exists yet (`Firmware::open_phoenix`
        // + the Phoenix `Loader::set_graphics` arm are the firmware lane's),
        // so the Phoenix graphics path is wired but unreachable: the display
        // stays display-only until that lane lands.
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: phoenix graphics firmware not loaded (no Firmware::open_phoenix yet); display only"
        );
        return;
    }
    let result = match crate::amdgpu_rdna2::apu_for_pci_id(gpu.chip.vid, gpu.chip.did) {
        Some(p) if p == &crate::amdgpu_rdna2::RAPHAEL => {
            crate::amdgpu_gfx_navi22::Firmware::open_raphael(gpu, fw_cap)
        }
        Some(p) if p == &crate::amdgpu_rdna2::REMBRANDT => {
            crate::amdgpu_gfx_navi22::Firmware::open_rembrandt(gpu, fw_cap)
        }
        _ => return,
    }
    .map_err(|e| alloc::format!("{e:?}"))
    .and_then(|set| {
        loader
            .set_graphics(set)
            .map_err(|e| alloc::format!("{e:?}"))
    });
    if let Err(why) = result {
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: graphics firmware not loaded ({why}); display only"
        );
    }
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
    /// Raphael's graphics engines, retained whether or not their bring-up
    /// finished: an engine may still reach memory it published.
    graphics: Option<crate::amdgpu_raphael_boot::ColdBoot>,
    /// Graphics owners a mode 2 recovery replaced. Kept, never reused, so
    /// the memory they published stays quarantined (Navi22's policy: each
    /// recovery leaks its old owners' carve-out).
    retired: Vec<crate::amdgpu_raphael_boot::ColdBoot>,
    /// Phoenix's graphics engines, same retention policy as Raphael's.
    /// Boxed: the owner is 2464 bytes and the boot future holds it across
    /// an await (see `graphics_boot_phoenix`); the box keeps that future
    /// and the start task's poll frame independent of the owner's size.
    /// Unreachable until the firmware lane lands `Firmware::open_phoenix`
    /// and the Phoenix `set_graphics` arm: no Phoenix set can be loaded
    /// today, so `start()` never fills this in.
    graphics_phoenix: Option<alloc::boxed::Box<crate::amdgpu_phoenix_boot::PhoenixColdBoot>>,
    /// Phoenix owners a mode 2 recovery replaced; same quarantine policy.
    retired_phoenix: Vec<crate::amdgpu_phoenix_boot::PhoenixColdBoot>,
    /// Strix's graphics engines, same retention policy as Phoenix's.
    /// Unreachable until the firmware lane lands `Firmware::open_strix`
    /// and the Strix `set_graphics` arm: no Strix set can be loaded today,
    /// so `start()` never fills this in.
    graphics_strix: Option<crate::amdgpu_strix_boot::StrixColdBoot>,
    /// Strix owners a mode 2 recovery replaced; same quarantine policy.
    /// Unread until the Strix recovery lane lands (`recover()` has no
    /// Strix arm yet — it falls through to `Busy`); the recovery lane
    /// pushes the replaced owner here, as `rebuild_graphics_phoenix`
    /// does for Phoenix.
    #[allow(dead_code, reason = "read by the Strix recovery lane")]
    retired_strix: Vec<crate::amdgpu_strix_boot::StrixColdBoot>,
    /// Where a system transition left the graphics (`GraphicsPm`).
    graphics_pm: GraphicsPm,
    /// The client buffers a hibernation moved out of the carve-out, with
    /// the allowed domains to put back at resume.
    evicted: Vec<(Arc<crate::amdgpu_gem::GemObject>, u64)>,
}
static DISPLAY: narf_lib::mutex::Mutex<Option<Display>> = narf_lib::mutex::Mutex::new(None);

/// The display owner, locked for Raphael's client path
/// (`amdgpu_rdna2_client`): the graphics coordinator lives beside the PSP
/// session that loaded it, so a client job takes the same lock the display
/// task holds across its bring-up and modesets.
pub(crate) struct Graphics(narf_lib::mutex::MutexGuard<'static, Option<Display>>);
impl Graphics {
    pub(crate) fn get(&mut self) -> Option<&mut crate::amdgpu_raphael_boot::ColdBoot> {
        self.0.as_mut()?.graphics.as_mut()
    }
    pub(crate) fn get_phoenix(
        &mut self,
    ) -> Option<&mut crate::amdgpu_phoenix_boot::PhoenixColdBoot> {
        self.0.as_mut()?.graphics_phoenix.as_deref_mut()
    }
    pub(crate) fn get_strix(&mut self) -> Option<&mut crate::amdgpu_strix_boot::StrixColdBoot> {
        self.0.as_mut()?.graphics_strix.as_mut()
    }
    /// The coordinator with the PSP session that loaded its VCN.
    pub(crate) fn media(
        &mut self,
    ) -> Option<(
        &mut crate::amdgpu_raphael_boot::ColdBoot,
        &mut crate::amdgpu_psp_ring::Psp,
    )> {
        let display = self.0.as_mut()?;
        let psp = display.loader.media_psp()?;
        Some((display.graphics.as_mut()?, psp))
    }
}
pub(crate) async fn graphics_owner() -> Graphics {
    Graphics(DISPLAY.lock().await)
}

pub(crate) fn start() -> bool {
    // Telemetry is independent of display: attach the APU SMU owner
    // first, so Renoir/Cezanne/Rembrandt get a temperature even though
    // `prepare()` refuses their display path (#1698). A refusal logs
    // and leaves the display bring-up to proceed without it.
    crate::amdgpu_apu_platform::attach();
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
        graphics: None,
        retired: Vec::new(),
        graphics_phoenix: None,
        retired_phoenix: Vec::new(),
        graphics_strix: None,
        retired_strix: Vec::new(),
        graphics_pm: GraphicsPm::Running,
        evicted: Vec::new(),
    });
    drop(owner);
    crate::amdgpu_usbc::observe_connectors();
    narf_scheduler::spawn(async {
        {
            let mut guard = DISPLAY.lock().await;
            let display = guard.as_mut().unwrap();
            // Boxed, like the graphics bring-up below: the PSP/DMUB boot,
            // sink discovery and arming would otherwise make this task's
            // own poll frame exceed the kernel stack-frame budget.
            let result = alloc::boxed::Box::pin(async {
                display.loader.boot(Default::default()).await?;
                display.loader.enable_notifications().await
            })
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
            if display.loader.graphics_booted() {
                // Boxed: these futures hold the whole bring-up, which inline
                // would make this task's own frame and future too large.
                // Strix first, checked by DID: the Phoenix branch below
                // matches on family, and Strix is its own family
                // (Family::Strix), so the order is defense in depth —
                // the DID check is the exact admission (one DID) and
                // stays even though the family check now agrees.
                let is_strix = crate::amdgpu::pci_device().is_some_and(|d| {
                    (d.id.vendor, d.id.device)
                        == (crate::amdgpu::AMD_VENDOR, crate::amdgpu::STRIX_POINT)
                });
                let is_phoenix = crate::amdgpu::pci_device().is_some_and(|d| {
                    crate::amdgpu::family_for_pci_id(d.id.vendor, d.id.device)
                        == Some(crate::amdgpu::Family::Phoenix)
                });
                if is_strix {
                    match display.loader.mes_start_addrs() {
                        Some(mes_start) => {
                            display.graphics_strix = alloc::boxed::Box::pin(graphics_boot_strix(
                                &display.pool,
                                mes_start,
                            ))
                            .await;
                            if let Some(graphics) = display.graphics_strix.as_mut() {
                                alloc::boxed::Box::pin(media_boot_strix(graphics)).await;
                                serve_clients_strix(graphics);
                                gate_graphics_strix(graphics).await;
                            }
                        }
                        None => {
                            use core::fmt::Write as _;
                            let _ = writeln!(
                                narf_console::Writer,
                                "amdgpu: strix graphics skipped: no MES entry points (firmware lane)"
                            );
                        }
                    }
                } else if is_phoenix {
                    match display.loader.mes_start_addrs() {
                        Some(mes_start) => {
                            display.graphics_phoenix = alloc::boxed::Box::pin(
                                graphics_boot_phoenix(&display.pool, mes_start),
                            )
                            .await;
                            if let Some(graphics) = display.graphics_phoenix.as_mut() {
                                alloc::boxed::Box::pin(media_boot_phoenix(graphics)).await;
                                serve_clients_phoenix(graphics);
                                gate_graphics_phoenix(graphics).await;
                            }
                        }
                        None => {
                            use core::fmt::Write as _;
                            let _ = writeln!(
                                narf_console::Writer,
                                "amdgpu: phoenix graphics skipped: no MES entry points (firmware lane)"
                            );
                        }
                    }
                } else {
                    let firmware = display.loader.graphics_versions();
                    display.graphics =
                        alloc::boxed::Box::pin(graphics_boot(&display.pool, firmware)).await;
                    if let Some(graphics) = display.graphics.as_mut() {
                        alloc::boxed::Box::pin(media_boot(graphics, &mut display.loader)).await;
                        serve_clients(graphics);
                        gate_graphics(graphics).await;
                    }
                }
            }
        }
        crate::amdgpu_usbc::finish_cycle();
        loop {
            if crate::amdgpu_usbc::begin_cycle() {
                let result = {
                    let mut guard = DISPLAY.lock().await;
                    alloc::boxed::Box::pin(guard.as_mut().unwrap().loader.discover_sinks()).await
                };
                match result {
                    Ok(found) => {
                        {
                            let mut guard = DISPLAY.lock().await;
                            alloc::boxed::Box::pin(arm(guard.as_mut().unwrap(), &found)).await;
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
    let Display {
        loader,
        stream,
        graphics,
        graphics_pm,
        ..
    } = display;
    if *graphics_pm == GraphicsPm::Idle {
        // s2idle without s0ix: Linux suspends nothing, the display included.
        return true;
    }
    // Stop the stream before the firmware: a pipe left fetching across a GPU
    // suspend would read scanout memory the resume path has not re-established.
    // The stream itself is kept, with the mode it was validated for, so resume
    // puts back the same one rather than re-deriving a possibly different mode.
    if let Some(stream) = stream.as_mut() {
        if narf_scheduler::block_on_spin(stream.pipeline.disable(loader)).is_err() {
            return false;
        }
    }
    if *graphics_pm == GraphicsPm::S0ix {
        // amdgpu_device_ip_suspend_phase2 with in_s0ix: the PSP keeps its TMR,
        // so the loader is not stopped.
        if let Some(graphics) = graphics.as_mut() {
            // SAFETY: the async prepare paused clients, drained the rings and
            // suspended media; the sync resume brings these back first.
            let result = narf_scheduler::block_on_spin(alloc::boxed::Box::pin(unsafe {
                graphics.suspend_s0ix()
            }));
            if let Err(error) = result {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: raphael s0ix suspend {error:?}"
                );
            }
        }
        return true;
    }
    if matches!(*graphics_pm, GraphicsPm::Quiesced | GraphicsPm::Freezing) {
        // The async prepare quiesced graphics. S3 powers the engines off,
        // which is the reset releasing the TMR under them needs; a
        // hibernation resets them here (`after_psp_stop`).
        // SAFETY: as above; `resume` boots the loader again before use.
        // Boxed: block_on_spin holds its future by value, and the PSP stop's
        // state has no business in this frame.
        let stopped = narf_scheduler::block_on_spin(alloc::boxed::Box::pin(unsafe {
            loader.stop_for_reset()
        }))
        .is_ok();
        let reset = || {
            let (Some(device), Some(graphics)) = (crate::amdgpu::pci_device(), graphics.as_mut())
            else {
                return false;
            };
            // SAFETY: quiesced at prepare and the TMR released just above;
            // the resume rebuilds every engine.
            narf_scheduler::block_on_spin(alloc::boxed::Box::pin(unsafe {
                graphics.mode2_reset(&device)
            }))
            .is_ok()
        };
        let (next, proceed) = after_psp_stop(*graphics_pm, stopped, reset);
        *graphics_pm = next;
        return proceed;
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
    let Display {
        loader,
        stream,
        graphics,
        graphics_pm,
        ..
    } = display;
    if *graphics_pm == GraphicsPm::Idle {
        // Nothing was suspended (see `prepare_graphics_idle`).
        return true;
    }
    let s0ix = *graphics_pm == GraphicsPm::S0ix;
    if s0ix {
        // amdgpu_device_ip_resume_phase1 with in_s0ix: COMMON, GMC, IH in
        // place. The PSP kept its TMR, so the loader is not booted.
        if let Some(graphics) = graphics.as_mut() {
            // SAFETY: `suspend_s0ix` ran and nothing touched the GPU since.
            let result = narf_scheduler::block_on_spin(alloc::boxed::Box::pin(unsafe {
                graphics.resume_s0ix()
            }));
            if let Err(error) = result {
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: raphael s0ix resume {error:?}"
                );
            }
        }
        // dm_resume's dm_dmub_hw_resume: DMCUB checked, and booted again from
        // the TMR only if S0i3 lost it; then its notifications.
        if narf_scheduler::block_on_spin(async {
            loader.resume_dmub(Default::default()).await?;
            loader.enable_notifications().await
        })
        .is_err()
        {
            return false;
        }
    } else if narf_scheduler::block_on_spin(async {
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
            // VRAM, system memory on an APU, survives an s0ix cycle.
            if !s0ix {
                running.scanout.clear().await;
            }
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
    /// Four blanked DCN3.1.4 pipes whose timing generators all run.
    fn registers() -> Vec<u32> {
        let mut regs = vec![0; 0x1cc2];
        for index in 0..4 {
            regs[0x5f3 + index * 0xdc] = 1;
            regs[0x1b41 + index * 0x80] = 1;
        }
        regs
    }
    /// Raphael's S3 resume does what suspend left undone: nothing for running
    /// graphics, a rebuild once the PSP released the TMR (the GPU lost
    /// power), and a mode 2 reset first when suspend stopped at the quiesce.
    fn raphael_s3_resume_work_follows_the_suspend_state() -> TestResult {
        if resume_work(GraphicsPm::Running) != ResumeWork::Nothing
            || resume_work(GraphicsPm::Stopped) != ResumeWork::Rebuild
            || resume_work(GraphicsPm::Quiesced) != ResumeWork::ResetThenRebuild
        {
            return TestResult::Fail("S3 resume work");
        }
        // A suspend-to-idle suspended nothing, so its resume does nothing:
        // no rebuild (the GPU was never reset) and no mode 2 reset.
        if resume_work(GraphicsPm::Idle) != ResumeWork::Nothing {
            return TestResult::Fail("s2idle resume work");
        }
        // A hibernation that froze resumes like S3 (restore or thaw find
        // the GPU power-cycled or reset); one whose PSP never stopped needs
        // the reset first.
        if resume_work(GraphicsPm::Frozen) != ResumeWork::Rebuild
            || resume_work(GraphicsPm::Freezing) != ResumeWork::ResetThenRebuild
        {
            return TestResult::Fail("S4 resume work");
        }
        // An s0ix cycle resumed the engines in place: no reset, no rebuild.
        if resume_work(GraphicsPm::S0ix) != ResumeWork::InPlace {
            return TestResult::Fail("s0ix resume work");
        }
        TestResult::Pass
    }
    /// amdgpu_pmops_freeze resets an APU after amdgpu_device_suspend: the
    /// sync suspend resets only a hibernation, only once the PSP stopped,
    /// and a failed reset fails the freeze.
    fn raphael_s4_freeze_resets_after_the_psp_stop() -> TestResult {
        use core::cell::Cell;
        use GraphicsPm::{Freezing, Frozen, Quiesced, Stopped};
        let resets = Cell::new(0);
        let run = |state, stopped, ok| {
            resets.set(0);
            let next = after_psp_stop(state, stopped, || {
                resets.set(resets.get() + 1);
                ok
            });
            (next, resets.get())
        };
        // S3: the power-off is the reset.
        if run(Quiesced, true, true) != ((Stopped, true), 0)
            || run(Quiesced, false, true) != ((Quiesced, false), 0)
        {
            return TestResult::Fail("S3 sync suspend reset");
        }
        // S4: reset once the PSP stopped; a failed reset fails the freeze.
        if run(Freezing, true, true) != ((Frozen, true), 1)
            || run(Freezing, true, false) != ((Stopped, false), 1)
            || run(Freezing, false, true) != ((Freezing, false), 0)
        {
            return TestResult::Fail("S4 freeze reset");
        }
        TestResult::Pass
    }
    /// After the freeze's eviction the carve-out may be lost (S4 powers it
    /// off, and firmware may reuse it before the image is restored): every
    /// unpinned client buffer's bytes are already in system memory, and
    /// nothing new can be placed in the withdrawn heap.
    fn raphael_s4_eviction_empties_the_carve_out() -> TestResult {
        use crate::amdgpu_gem::{GemState, VramHeap};
        const CARD: u32 = 0xe1c5; // linux: n/a (test card index)
        const BASE: u64 = 0x8_0000_0000; // linux: n/a (test carve-out MC address)
        struct Registered;
        impl Drop for Registered {
            fn drop(&mut self) {
                crate::amdgpu_gem::unregister_vram_heap(CARD);
            }
        }
        let mut memory = vec![0u8; 16 * 4096];
        let map = narf_bus::MmioRegion {
            phys: narf_memory::PhysAddr::new(0xb900_0000),
            virt: memory.as_mut_ptr() as u64,
            len: memory.len() as u64,
            kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
        };
        // SAFETY: this test exclusively owns memory until the registered heap
        // and every object have been dropped; no hardware reaches it.
        let pool = unsafe { crate::amdgpu_vram::Pool::from_owned_range(map, BASE) }.unwrap();
        let heap = VramHeap {
            pool: pool.clone(),
            fb_base: BASE,
            fb_offset: BASE,
            unmapped: None,
        };
        let _registered = Registered;
        crate::amdgpu_gem::register_vram_heap(CARD, heap.clone());
        let state = GemState::for_card(CARD);
        let full = pool.available();
        let Some(object) = state
            .create_dumb(64, 4, 32)
            .ok()
            .and_then(|(handle, _, _)| state.object(handle))
        else {
            return TestResult::Fail("client buffer in the carve-out");
        };
        let Some(at) = object.placement().gpu_at(0x123) else {
            return TestResult::Fail("client buffer address");
        };
        let at = (at - BASE) as usize;
        memory[at..at + 4].copy_from_slice(&0x00c0_ffeeu32.to_le_bytes());
        let mut back = [0u8; 4];
        if object.system()
            || object.placement().read_bytes(0x123, &mut back).is_none()
            || back != 0x00c0_ffeeu32.to_le_bytes()
        {
            return TestResult::Fail("client buffer not in the carve-out");
        }
        let evicted = narf_scheduler::block_on_spin(async {
            let gate = crate::amdgpu_gem::lock_placement(CARD).await;
            evict_for_hibernation(&gate, Some(heap.clone())).await
        });
        let Ok(evicted) = evicted else {
            return TestResult::Fail("hibernation eviction");
        };
        if !object.system() || evicted.len() != 1 || pool.available() != full {
            return TestResult::Fail("the eviction left a buffer in the carve-out");
        }
        if state
            .create_dumb(64, 4, 32)
            .is_ok_and(|(handle, _, _)| state.object(handle).is_some_and(|o| !o.system()))
        {
            return TestResult::Fail("a buffer was placed in the withdrawn heap");
        }
        // S4: the carve-out's contents are gone.
        memory.fill(0);
        back = [0; 4];
        if object.placement().read_bytes(0x123, &mut back).is_none()
            || back != 0x00c0_ffeeu32.to_le_bytes()
        {
            return TestResult::Fail("client bytes did not survive the carve-out");
        }
        crate::amdgpu_gem::restore_domains(evicted);
        drop(object);
        drop(state);
        TestResult::Pass
    }
    /// amdgpu_acpi_is_s0ix_active for an APU suspending to idle, in Linux's
    /// order: GFXOFF allowed, the FADT's LOW_POWER_S0, then AMD PMC, which
    /// counts once `amd_pmc` registered its LPS0 handler.
    fn raphael_s0ix_follows_amdgpu_acpi_is_s0ix_active() -> TestResult {
        for (gfxoff, lps0, pmc, want) in [
            (false, true, true, S0ix::NoGfxoff),
            (true, false, true, S0ix::NoLowPowerS0),
            (true, true, false, S0ix::NoPmc),
            (true, true, true, S0ix::Active),
            (false, false, false, S0ix::NoGfxoff),
        ] {
            if s0ix(gfxoff, lps0, pmc) != want {
                return TestResult::Fail("s0ix decision order");
            }
        }
        // The kernel-test boot binds no AMD PMC (no ACPI PMC device).
        if s0ix(true, true, amd_pmc()) == S0ix::Active {
            return TestResult::Fail("s0ix active without an AMD PMC driver");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/raphael-reset",
        raphael_s3_resume_work_follows_the_suspend_state
    );
    kernel_test_in!(
        "drivers/gpu/raphael-reset",
        raphael_s0ix_follows_amdgpu_acpi_is_s0ix_active
    );
    kernel_test_in!(
        "drivers/gpu/raphael-reset",
        raphael_s4_freeze_resets_after_the_psp_stop
    );
    kernel_test_in!(
        "drivers/gpu/raphael-reset",
        raphael_s4_eviction_empties_the_carve_out
    );
    /// Every literal here is read off the AMD header, never off the row it
    /// checks. One case per row, so adding a GPU means adding a case: a new
    /// row with no case is a window nothing has verified.
    fn platform_register_windows_match_the_amd_headers() -> TestResult {
        // `gc/gc_11_0_0_offset.h`: regGCVM_CONTEXT0_CNTL 0x1688 _BASE_IDX 0,
        // regGCVM_CONTEXT15_CNTL 0x1697. Every GC 11.0.x revision uses it
        // except 11.0.3: `gc/gc_11_0_3_offset.h` puts the whole GCMC/GCVM
        // block 0x10 higher, CONTEXT0 at 0x1698 (CONTEXT15 0x16a7). No
        // gc_11_0_2 header exists; Linux drives 11.0.2 with the 11.0.0
        // function table (`gmc_v11_0_set_gfxhub_funcs` default).
        let gfxhub_expected = [
            // gc_12_0_0_offset.h: regGCVM_CONTEXT0_CNTL 0x1624 _BASE_IDX 0.
            VmWindow {
                version: (12, 0, 1),
                base_idx: 0,
                ctx0_cntl: 0x1624,
            },
            // Navi31 (RX 7900), GC 11.0.0.
            VmWindow {
                version: (11, 0, 0),
                base_idx: 0,
                ctx0_cntl: 0x1688,
            },
            // Navi33 (RX 7600), GC 11.0.2: same 11.0.0 table as Navi31.
            VmWindow {
                version: (11, 0, 2),
                base_idx: 0,
                ctx0_cntl: 0x1688,
            },
            // Navi32 (RX 7800 XT), GC 11.0.3: the block sits 0x10 higher.
            VmWindow {
                version: (11, 0, 3),
                base_idx: 0,
                ctx0_cntl: 0x1698,
            },
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
            VmWindow {
                version: (10, 3, 0),
                base_idx: 0,
                ctx0_cntl: 0x15fc,
            },
            VmWindow {
                version: (10, 3, 4),
                base_idx: 0,
                ctx0_cntl: 0x15fc,
            },
            VmWindow {
                version: (10, 3, 5),
                base_idx: 0,
                ctx0_cntl: 0x15fc,
            },
            // gc_10_3_0_offset.h: mmGCVM_CONTEXT0_CNTL 0x15fc _BASE_IDX 0;
            // gmc_v10_0.c gives GC 10.3.6 (Raphael) gfxhub_v2_1.
            VmWindow {
                version: (10, 3, 6),
                base_idx: 0,
                ctx0_cntl: 0x15fc,
            },
            VmWindow {
                version: (10, 3, 2),
                base_idx: 0,
                ctx0_cntl: 0x15fc,
            },
            // gc_12_0_0_offset.h again, for GC 12.0.0.
            VmWindow {
                version: (12, 0, 0),
                base_idx: 0,
                ctx0_cntl: 0x1624,
            },
            // gc_9_0_offset.h: mmVM_CONTEXT0_CNTL 0x0880 _BASE_IDX 0;
            // gmc_v9_0.c gives every non-multi-AID GFX9 part
            // gfxhub_v1_0_funcs. Renoir / Cezanne are GC 9.3.0.
            VmWindow {
                version: (9, 3, 0),
                base_idx: 0,
                ctx0_cntl: 0x0880,
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
                version: (4, 1, 0),
                base_idx: 0,
                ctx0_cntl: 0x0564,
            },
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
            VmWindow {
                version: (2, 1, 1),
                base_idx: 0,
                ctx0_cntl: 0x06c0,
            },
            VmWindow {
                version: (2, 1, 2),
                base_idx: 0,
                ctx0_cntl: 0x06c0,
            },
            // mmhub_2_3_0_offset.h: mmMMVM_CONTEXT0_CNTL 0x0740 _BASE_IDX 1;
            // gmc_v10_0.c gives MMHUB 2.3.0, 2.4.0 and 2.4.1 mmhub_v2_3.
            VmWindow {
                version: (2, 3, 0),
                base_idx: 1,
                ctx0_cntl: 0x0740,
            },
            VmWindow {
                version: (2, 4, 0),
                base_idx: 1,
                ctx0_cntl: 0x0740,
            },
            VmWindow {
                version: (2, 4, 1),
                base_idx: 1,
                ctx0_cntl: 0x0740,
            },
            VmWindow {
                version: (2, 1, 0),
                base_idx: 0,
                ctx0_cntl: 0x06c0,
            },
        ];
        if MMHUB_WINDOWS != mmhub_expected {
            return TestResult::Fail("an MMHUB row does not match its mmhub_3_0_x_offset.h");
        }
        // GFX9's MMHUB table: gmc_v9_0.c sends both (1, 5, 0) and
        // (2, 4, 0) to mmhub_v1_0_funcs, mmhub_1_0_offset.h:
        // mmVM_CONTEXT0_CNTL 0x06c0 _BASE_IDX 0, last 0x06cf.
        let mmhub_gfx9_expected = [
            VmWindow {
                version: (1, 5, 0),
                base_idx: 0,
                ctx0_cntl: 0x06c0,
            },
            VmWindow {
                version: (2, 4, 0),
                base_idx: 0,
                ctx0_cntl: 0x06c0,
            },
        ];
        if MMHUB_WINDOWS_GFX9 != mmhub_gfx9_expected {
            return TestResult::Fail("a GFX9 MMHUB row does not match mmhub_1_0_offset.h");
        }
        // regGCVM_CONTEXT15_CNTL 0x1697, regMMVM_CONTEXT15_CNTL 0x074f: both
        // hubs run sixteen contexts one dword apart, and the window's `last`
        // must reach the sixteenth.
        if VM_CONTEXTS != 16 || VM_CONTEXT_ENABLE != 0x1 {
            return TestResult::Fail("sixteen contexts, ENABLE_CONTEXT in bit 0");
        }
        {
            use crate::amdgpu_psp_ring::RegWindow as _;
            if GFXHUB_WINDOWS[1].last() != 0x1697
                || MMHUB_WINDOWS[1].last() != 0x074f
                || MMHUB_WINDOWS_GFX9[0].last() != 0x06cf
                || MMHUB_WINDOWS_GFX9[1].last() != 0x06cf
            {
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
            viewport_start_mask: 0x3fff,
            pitch_mask: 0x3fff,
            sw_mode_mask: 0x1f,
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
        let dcn300_expected = SurfaceWindow {
            version: (3, 0, 0),
            pipes: 6,
            ..dcn314_expected
        };
        let dcn401_expected = SurfaceWindow {
            version: (4, 0, 1),
            viewport_dimension: 0x05eb,
            hubp_cntl: 0x05f4,
            surface_control: 0x0612,
            surface_inuse: 0x0618,
            surface_earliest_inuse: 0x061c,
            cursor_control: 0x0679,
            cursor_address: 0x067a,
            cursor_size: 0x067c,
            otg_control: 0x1b43,
            viewport_start_mask: 0xffff,
            pitch_mask: 0xffff,
            sw_mode_mask: 7,
            ..dcn314_expected
        };
        let dcn410_expected = SurfaceWindow {
            version: (4, 1, 0),
            ..dcn401_expected
        };
        if SURFACE_WINDOWS
            != [
                SurfaceWindow {
                    version: (3, 0, 2),
                    pipes: 5,
                    ..dcn300_expected
                },
                SurfaceWindow {
                    version: (3, 0, 3),
                    pipes: 2,
                    ..dcn300_expected
                },
                dcn314_expected,
                // dcn/dcn_3_1_5_offset.h: every id above at the same offset on
                // _BASE_IDX 2 (HUBP1 0x6c1, OTG1/3_OTG_CONTROL 0x1bc1/0x1cc1).
                SurfaceWindow {
                    version: (3, 1, 5),
                    ..dcn314_expected
                },
                dcn350_expected,
                dcn300_expected,
                dcn401_expected,
                dcn410_expected,
                // dcn/dcn_2_1_0_offset.h: the DCN 2.1 surface window is
                // DCN 3.1.4's (HUBP stride 0xdc, OTG stride 0x80, 4
                // pipes per dcn21_resource.c).
                SurfaceWindow {
                    version: (2, 1, 0),
                    ..dcn314_expected
                },
            ]
        {
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
        if DCN_3_0_0.last_reg() != 0x1dc1
            || DCN_3_0_0.cursor_size + 5 * DCN_3_0_0.pipe_stride != 0x0ac7
        {
            return TestResult::Fail("DCN3.0 inventory stops before the sixth pipe");
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
    fn navi22_inventory_includes_the_sixth_pipe() -> TestResult {
        let mut regs = vec![0; 0x1dc2];
        for pipe in 0..6 {
            regs[0x5f3 + pipe * 0xdc] = 1;
        }
        regs[0x1dc1] = 1; // OTG5_OTG_CONTROL.OTG_MASTER_EN
        regs[0xa3f] = 0;
        regs[0xa31] = 8; // HUBP5 surface format
        regs[0xa36] = (1080 << 16) | 1920;
        regs[0xa53] = 1919;
        regs[0xa56] = 0x800000;
        regs[0xa57] = 2;
        regs[0xac4] = 1 | (2 << 8);
        regs[0xac5] = 0x1800000;
        regs[0xac6] = 2;
        regs[0xac7] = (64 << 16) | 64;
        let ranges = scan_surfaces(&DCN_3_0_0, |r| regs[r as usize]).unwrap();
        if ranges != [0x2_00800000..0x2_00fe9000, 0x2_01800000..0x2_01804000] {
            return TestResult::Fail("sixth-pipe scanout/cursor missing or sized incorrectly");
        }
        regs[0xa33] = 1;
        if scan_surfaces(&DCN_3_0_0, |r| regs[r as usize]).is_ok() {
            return TestResult::Fail("sixth-pipe tiled surface accepted as a linear buffer");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/vram", navi22_inventory_includes_the_sixth_pipe);
    /// dcn10_init_pipes gates on is_tg_enabled: an unblanked HUBP behind a
    /// stopped OTG (GOP leaves unused pipes like this) is not a live scanout,
    /// so its stale, unsupported surface state must not fail the inventory.
    fn navi22_inventory_ignores_pipes_without_a_running_otg() -> TestResult {
        let mut regs = vec![0; 0x1dc2];
        for pipe in 0..6 {
            regs[0x5e5 + pipe * 0xdc] = 12; // AYCrCb8888: refused if scanned
            regs[0x5e7 + pipe * 0xdc] = 1; // tiled
            regs[0x678 + pipe * 0xdc] = 1; // mono cursor: refused if scanned
        }
        if scan_surfaces(&DCN_3_0_0, |r| regs[r as usize]) != Ok(alloc::vec::Vec::new()) {
            return TestResult::Fail("pipe with a stopped OTG treated as live");
        }
        regs[0x1b41] = 1;
        if scan_surfaces(&DCN_3_0_0, |r| regs[r as usize]).is_ok() {
            return TestResult::Fail("running OTG0's unsupported surface accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/vram",
        navi22_inventory_ignores_pipes_without_a_running_otg
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
