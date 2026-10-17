//! Navi22 DCN3.0 and Phoenix DCN3.1.4 hub pixel pipe. Programs the surface a pipe fetches and the
//! request, latency and throttle registers that pace that fetch. Offsets and
//! fields are `dcn_3_1_4_offset.h`/`dcn_3_1_4_sh_mask.h` at DCN base index 2;
//! sequencing follows Linux `dcn20_hubp.c` (`hubp2_program_requestor`,
//! `hubp2_program_deadline`, `hubp2_setup_interdependent`,
//! `hubp2_set_blank_regs`) and `dcn30_hubp.c::hubp3_program_surface_config`.
//!
//! The pacing values come from [`crate::amdgpu_dml_regs`], never from constants:
//! a HUBP programmed with someone else's deadlines underflows.
use crate::{
    amdgpu::AmdGpu, amdgpu_dcn_clk::Error, amdgpu_dcn_profile::Profile, amdgpu_dml::Format,
    amdgpu_dml_regs::Registers,
};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, CapError, CapOp, Write};

// HUBP block, stride 0xdc.
// Profile selects DCN30 or DCN314; shared ids below were compared against
// both Linux offset and mask headers. Generation differences stay explicit.
// linux-ctx: hdr=dcn seg=2
const DCSURF_SURFACE_CONFIG: u64 = 0x05e5; // linux: mmHUBP0_DCSURF_SURFACE_CONFIG
const DCSURF_TILING_CONFIG: u64 = 0x05e7; // linux: mmHUBP0_DCSURF_TILING_CONFIG
const DCSURF_PRI_VIEWPORT_START: u64 = 0x05e9; // linux: mmHUBP0_DCSURF_PRI_VIEWPORT_START
const DCSURF_PRI_VIEWPORT_DIMENSION: u64 = 0x05ea; // linux: mmHUBP0_DCSURF_PRI_VIEWPORT_DIMENSION
const DCHUBP_REQ_SIZE_CONFIG: u64 = 0x05f1; // linux: mmHUBP0_DCHUBP_REQ_SIZE_CONFIG
const DCHUBP_REQ_SIZE_CONFIG_C: u64 = 0x05f2; // linux: mmHUBP0_DCHUBP_REQ_SIZE_CONFIG_C
const DCHUBP_CNTL: u64 = 0x05f3; // linux: mmHUBP0_DCHUBP_CNTL
                                 // HUBPREQ block, same stride.
const DCSURF_SURFACE_PITCH: u64 = 0x0607; // linux: mmHUBPREQ0_DCSURF_SURFACE_PITCH
                                          // linux: mmHUBPREQ0_DCSURF_PRIMARY_SURFACE_ADDRESS
const DCSURF_PRIMARY_SURFACE_ADDRESS: u64 = 0x060a;
// linux: mmHUBPREQ0_DCSURF_PRIMARY_SURFACE_ADDRESS_HIGH
const DCSURF_PRIMARY_SURFACE_ADDRESS_HIGH: u64 = 0x060b;
const DCSURF_SURFACE_CONTROL: u64 = 0x061a; // linux: mmHUBPREQ0_DCSURF_SURFACE_CONTROL
const DCN_EXPANSION_MODE: u64 = 0x0629; // linux: mmHUBPREQ0_DCN_EXPANSION_MODE
const DCN_TTU_QOS_WM: u64 = 0x062a; // linux: mmHUBPREQ0_DCN_TTU_QOS_WM
const DCN_GLOBAL_TTU_CNTL: u64 = 0x062b; // linux: mmHUBPREQ0_DCN_GLOBAL_TTU_CNTL
const DCN_SURF0_TTU_CNTL0: u64 = 0x062c; // linux: mmHUBPREQ0_DCN_SURF0_TTU_CNTL0
const DCN_SURF0_TTU_CNTL1: u64 = 0x062d; // linux: mmHUBPREQ0_DCN_SURF0_TTU_CNTL1
const BLANK_OFFSET_0: u64 = 0x0644; // linux: mmHUBPREQ0_BLANK_OFFSET_0
const BLANK_OFFSET_1: u64 = 0x0645; // linux: mmHUBPREQ0_BLANK_OFFSET_1
const DST_DIMENSIONS: u64 = 0x0646; // linux: mmHUBPREQ0_DST_DIMENSIONS
const DST_AFTER_SCALER: u64 = 0x0647; // linux: mmHUBPREQ0_DST_AFTER_SCALER
const PREFETCH_SETTINGS: u64 = 0x0648; // linux: mmHUBPREQ0_PREFETCH_SETTINGS
const VBLANK_PARAMETERS_0: u64 = 0x064a; // linux: mmHUBPREQ0_VBLANK_PARAMETERS_0
const VBLANK_PARAMETERS_1: u64 = 0x064b; // linux: mmHUBPREQ0_VBLANK_PARAMETERS_1
const NOM_PARAMETERS_0: u64 = 0x0652; // linux: mmHUBPREQ0_NOM_PARAMETERS_0
const NOM_PARAMETERS_1: u64 = 0x0653; // linux: mmHUBPREQ0_NOM_PARAMETERS_1
const PER_LINE_DELIVERY_PRE: u64 = 0x065a; // linux: mmHUBPREQ0_PER_LINE_DELIVERY_PRE
const PER_LINE_DELIVERY: u64 = 0x065b; // linux: mmHUBPREQ0_PER_LINE_DELIVERY
const REF_FREQ_TO_PIX_FREQ: u64 = 0x065d; // linux: mmHUBPREQ0_REF_FREQ_TO_PIX_FREQ
                                          // HUBPRET block, same stride.
const HUBPRET_CONTROL: u64 = 0x066c; // linux: mmHUBPRET0_HUBPRET_CONTROL
const STRIDE: u64 = 0xdc; // linux: mmHUBP1_DCSURF_SURFACE_CONFIG - mmHUBP0_DCSURF_SURFACE_CONFIG
#[cfg(feature = "kernel-test")]
const LAST_REG: u32 = (HUBPRET_CONTROL + 3 * STRIDE) as u32; // linux: n/a (test-only bank bound)
/// `DC_SW_LINEAR`. No other swizzle is modelled by the mode math.
const SW_MODE_LINEAR: u32 = 0; // linux: DC_SW_LINEAR@dc

// Field positions, from `dcn_3_1_4_sh_mask.h`. The `DCHUBP_REQ_SIZE_CONFIG`
// run is NOT evenly spaced — three bits sit unused between `MIN_CHUNK_SIZE`
// and `META_CHUNK_SIZE`, and two more between `MIN_META_CHUNK_SIZE` and
// `DPTE_GROUP_SIZE`:
//
//   SWATH_HEIGHT          0x00000007   shift 0
//   PTE_ROW_HEIGHT_LINEAR 0x00000070   shift 4
//   CHUNK_SIZE            0x00000700   shift 8
//   MIN_CHUNK_SIZE        0x00001800   shift 11
//   META_CHUNK_SIZE       0x00030000   shift 16
//   MIN_META_CHUNK_SIZE   0x000C0000   shift 18
//   DPTE_GROUP_SIZE       0x00700000   shift 20
//   VM_GROUP_SIZE         0x07000000   shift 24
//
// LINUX-GAP: `META_CHUNK_SIZE` was written at shift 14 and
// `MIN_META_CHUNK_SIZE` at 17 — as though the run continued at three-bit
// spacing from `MIN_CHUNK_SIZE`. Neither value is zero on this path
// (`amdgpu_dml` gives `META_CHUNK_BYTES` 2048 → 1 and `MIN_META_CHUNK_BYTES`
// 256 → 3), so the whole-register write put 1 into reserved bits 15:14 and
// split 3 across `META_CHUNK_SIZE`'s high bit and `MIN_META_CHUNK_SIZE`'s low
// one, landing META_CHUNK_SIZE = 2 and MIN_META_CHUNK_SIZE = 1. The smoke test
// composed its expectation with the same two shifts, so it passed.
const REQ_SWATH_HEIGHT_SHIFT: u32 = 0; // linux: HUBP0_DCHUBP_REQ_SIZE_CONFIG__SWATH_HEIGHT__SHIFT
                                       // linux: HUBP0_DCHUBP_REQ_SIZE_CONFIG__PTE_ROW_HEIGHT_LINEAR__SHIFT
const REQ_PTE_ROW_HEIGHT_LINEAR_SHIFT: u32 = 4;
const REQ_CHUNK_SIZE_SHIFT: u32 = 8; // linux: HUBP0_DCHUBP_REQ_SIZE_CONFIG__CHUNK_SIZE__SHIFT
                                     // linux: HUBP0_DCHUBP_REQ_SIZE_CONFIG__MIN_CHUNK_SIZE__SHIFT
const REQ_MIN_CHUNK_SIZE_SHIFT: u32 = 11;
// linux: HUBP0_DCHUBP_REQ_SIZE_CONFIG__META_CHUNK_SIZE__SHIFT
const REQ_META_CHUNK_SIZE_SHIFT: u32 = 16;
// linux: HUBP0_DCHUBP_REQ_SIZE_CONFIG__MIN_META_CHUNK_SIZE__SHIFT
const REQ_MIN_META_CHUNK_SIZE_SHIFT: u32 = 18;
// linux: HUBP0_DCHUBP_REQ_SIZE_CONFIG__DPTE_GROUP_SIZE__SHIFT
const REQ_DPTE_GROUP_SIZE_SHIFT: u32 = 20;
// linux: HUBP0_DCHUBP_REQ_SIZE_CONFIG__VM_GROUP_SIZE__SHIFT
const REQ_VM_GROUP_SIZE_SHIFT: u32 = 24;

// `HUBPRET_CONTROL`, same header:
//
//   DET_BUF_PLANE1_BASE_ADDRESS 0x00001FF0   PACK_3TO2_ELEMENT_DISABLE 0x8000
//   CROSSBAR_SRC_ALPHA          0x00030000   CROSSBAR_SRC_Y_G   0x000C0000
//   CROSSBAR_SRC_CB_B           0x00300000   CROSSBAR_SRC_CR_R  0x00C00000
//
// LINUX-GAP: the detile-buffer field was masked as `0xfff << 4`, three bits
// wider than the nine it has, so the update also cleared reserved bits 14:13
// and `PACK_3TO2_ELEMENT_DISABLE` at 15 — a field no DCN hubp code in Linux
// writes, and so one whose reset value this had no business changing.
// linux: n/a (DCN 3.1.4 path; DCN30 mask 0xfff is applied inline below)
const DET_BUF_PLANE1_BASE_ADDRESS: u32 = 0x0000_1FF0;
/// `CROSSBAR_SRC_CB_B` | `CROSSBAR_SRC_CR_R`. `hubp2_program_pixel_format`
/// updates only these two of the four crossbar fields.
// linux: HUBPRET0_HUBPRET_CONTROL__CROSSBAR_SRC_CB_B_MASK | HUBPRET0_HUBPRET_CONTROL__CROSSBAR_SRC_CR_R_MASK
const CROSSBAR_CB_B_AND_CR_R: u32 = 0x0030_0000 | 0x00C0_0000;
// linux: HUBPRET0_HUBPRET_CONTROL__CROSSBAR_SRC_CB_B__SHIFT
const CROSSBAR_SRC_CB_B_SHIFT: u32 = 20;
// linux: HUBPRET0_HUBPRET_CONTROL__CROSSBAR_SRC_CR_R__SHIFT
const CROSSBAR_SRC_CR_R_SHIFT: u32 = 22;
/// `red_bar` / `blue_bar` for a non-byte-swapped A*GB surface, per
/// `hubp2_program_pixel_format`. An ABGR surface swaps them to 2 and 3.
// linux: n/a (literal in dcn20_hubp.c:hubp2_program_pixel_format, red_bar)
const CROSSBAR_SRC_CR_R_ARGB: u32 = 3;
// linux: n/a (literal in dcn20_hubp.c:hubp2_program_pixel_format, blue_bar)
const CROSSBAR_SRC_CB_B_ARGB: u32 = 2;
/// HUBP surface addresses are 48-bit and must land on a 256-byte request.
const ADDRESS_BITS: u32 = 48; // linux: n/a (hw width: 32-bit ADDRESS + 16-bit ADDRESS_HIGH field)
const ADDRESS_ALIGN: u64 = 256; // linux: n/a (NARF policy: 256-byte request alignment)

trait Io: Send {
    fn read(&mut self, reg: u64) -> u32;
    fn write(&mut self, reg: u64, value: u32);
}
#[derive(Debug)]
struct Mmio {
    regs: crate::amdgpu_reg_window::Window,
    base: u64,
}
impl Io for Mmio {
    fn read(&mut self, reg: u64) -> u32 {
        // SAFETY: constructor bounds the DCN bank and retains the mapping.
        unsafe { self.regs.read32(self.base + reg * 4) }
    }
    fn write(&mut self, reg: u64, value: u32) {
        // SAFETY: same bounded bank; this is the sole owner of this pipe.
        unsafe { self.regs.write32(self.base + reg * 4, value) };
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
async fn delay(ms: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_ms(ms).as_instant()).await;
}
/// `hubp2_program_pixel_format`: the format code is not the bit depth.
fn pixel_format(format: Format) -> u32 {
    match format {
        // linux: n/a (literal in dcn20_hubp.c:hubp2_program_pixel_format, RGB565)
        Format::Rgb16 => 3,
        // linux: n/a (literal in dcn20_hubp.c:hubp2_program_pixel_format, ARGB8888)
        Format::Rgb32 => 8,
        // linux: n/a (literal in dcn20_hubp.c:hubp2_program_pixel_format, ARGB16161616)
        Format::Rgb64 => 26,
    }
}
/// The scanout surface this pipe fetches. The address is a GPU address inside
/// the caller's owned VRAM, not a host physical address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Surface {
    pub address: u64,
    pub format: Format,
    pub pitch: u32,
    pub viewport_width: u32,
    pub viewport_height: u32,
}

#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    instance: u8,
    blanked: bool,
    profile: Profile,
    /// Blanks whose HUBP_NO_OUTSTANDING_REQ wait expired (Linux logs the
    /// REG_WAIT timeout and blanks anyway).
    blank_stalls: u32,
}
impl<I: Io> Engine<I> {
    fn reg(&self, reg: u64) -> u64 {
        reg + self.instance as u64 * STRIDE
    }
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)
    }
    fn set(&mut self, reg: u64, value: u32) -> Result<(), Error> {
        let reg = self.reg(reg);
        self.access(|io| io.write(reg, value))
    }
    fn update(&mut self, reg: u64, mask: u32, value: u32) -> Result<(), Error> {
        let reg = self.reg(reg);
        self.access(|io| {
            let old = io.read(reg);
            if old == u32::MAX {
                return Err(Error::DeviceGone);
            }
            io.write(reg, (old & !mask) | (value & mask));
            Ok(())
        })?
    }
    /// `hubp2_program_requestor` and `hubp2_program_deadline`: the request sizes
    /// and the per-plane deadlines. Chroma counterparts are zeroed rather than
    /// left behind, so a previous owner's chroma plane cannot keep fetching.
    fn program_pacing(&mut self, registers: &Registers) -> Result<(), Error> {
        let rq = &registers.rq;
        let dlg = &registers.dlg;
        let ttu = &registers.ttu;
        self.update(
            HUBPRET_CONTROL,
            (if self.profile == Profile::Navi22 {
                // linux-lit: 0xfff=HUBPRET0_HUBPRET_CONTROL__DET_BUF_PLANE1_BASE_ADDRESS_MASK
                0x00000fff
            } else {
                DET_BUF_PLANE1_BASE_ADDRESS
            }) | CROSSBAR_CB_B_AND_CR_R,
            // No second detile plane, and the RGB crossbar is straight through.
            CROSSBAR_SRC_CR_R_ARGB << CROSSBAR_SRC_CR_R_SHIFT
                | CROSSBAR_SRC_CB_B_ARGB << CROSSBAR_SRC_CB_B_SHIFT,
        )?;
        self.set(
            DCN_EXPANSION_MODE,
            rq.drq_expansion_mode
                // linux-lit: 2=HUBPREQ0_DCN_EXPANSION_MODE__CRQ_EXPANSION_MODE__SHIFT
                | rq.crq_expansion_mode << 2
                // linux-lit: 4=HUBPREQ0_DCN_EXPANSION_MODE__MRQ_EXPANSION_MODE__SHIFT
                | rq.mrq_expansion_mode << 4
                // linux-lit: 6=HUBPREQ0_DCN_EXPANSION_MODE__PRQ_EXPANSION_MODE__SHIFT
                | rq.prq_expansion_mode << 6,
        )?;
        self.set(
            DCHUBP_REQ_SIZE_CONFIG,
            rq.swath_height << REQ_SWATH_HEIGHT_SHIFT
                | rq.pte_row_height_linear << REQ_PTE_ROW_HEIGHT_LINEAR_SHIFT
                | rq.chunk_size << REQ_CHUNK_SIZE_SHIFT
                | rq.min_chunk_size << REQ_MIN_CHUNK_SIZE_SHIFT
                | rq.meta_chunk_size << REQ_META_CHUNK_SIZE_SHIFT
                | rq.min_meta_chunk_size << REQ_MIN_META_CHUNK_SIZE_SHIFT
                | rq.dpte_group_size << REQ_DPTE_GROUP_SIZE_SHIFT
                | rq.mpte_group_size << REQ_VM_GROUP_SIZE_SHIFT,
        )?;
        // There is no chroma plane on this path.
        self.set(DCHUBP_REQ_SIZE_CONFIG_C, 0)?;

        self.set(
            BLANK_OFFSET_0,
            // linux-lit: 16=HUBPREQ0_BLANK_OFFSET_0__DLG_V_BLANK_END__SHIFT
            dlg.refcyc_h_blank_end | dlg.dlg_vblank_end << 16,
        )?;
        self.set(BLANK_OFFSET_1, dlg.min_dst_y_next_start)?;
        self.set(DST_DIMENSIONS, dlg.refcyc_per_htotal)?;
        self.set(
            DST_AFTER_SCALER,
            // linux-lit: 16=HUBPREQ0_DST_AFTER_SCALER__DST_Y_AFTER_SCALER__SHIFT
            dlg.refcyc_x_after_scaler | dlg.dst_y_after_scaler << 16,
        )?;
        self.set(REF_FREQ_TO_PIX_FREQ, dlg.ref_freq_to_pix_freq)?;
        self.set(VBLANK_PARAMETERS_1, dlg.refcyc_per_pte_group_vblank_l)?;
        self.set(NOM_PARAMETERS_0, dlg.dst_y_per_pte_row_nom_l)?;
        self.set(NOM_PARAMETERS_1, dlg.refcyc_per_pte_group_nom_l)?;
        self.set(PER_LINE_DELIVERY, dlg.refcyc_per_line_delivery_l)?;
        self.set(
            PREFETCH_SETTINGS,
            // linux-lit: 24=HUBPREQ0_PREFETCH_SETTINGS__DST_Y_PREFETCH__SHIFT
            dlg.vratio_prefetch | dlg.dst_y_prefetch << 24,
        )?;
        self.set(
            VBLANK_PARAMETERS_0,
            // linux-lit: 8=HUBPREQ0_VBLANK_PARAMETERS_0__DST_Y_PER_ROW_VBLANK__SHIFT
            dlg.dst_y_per_vm_vblank | dlg.dst_y_per_row_vblank << 8,
        )?;
        self.set(PER_LINE_DELIVERY_PRE, dlg.refcyc_per_line_delivery_pre_l)?;

        self.set(
            DCN_TTU_QOS_WM,
            // linux-lit: 16=HUBPREQ0_DCN_TTU_QOS_WM__QoS_LEVEL_HIGH_WM__SHIFT
            ttu.qos_level_low_wm | ttu.qos_level_high_wm << 16,
        )?;
        self.set(
            DCN_GLOBAL_TTU_CNTL,
            // linux-lit: 28=HUBPREQ0_DCN_GLOBAL_TTU_CNTL__QoS_LEVEL_FLIP__SHIFT
            ttu.min_ttu_vblank | ttu.qos_level_flip << 28,
        )?;
        self.set(
            DCN_SURF0_TTU_CNTL0,
            ttu.refcyc_per_req_delivery_l
                // linux-lit: 24=HUBPREQ0_DCN_SURF0_TTU_CNTL0__QoS_LEVEL_FIXED__SHIFT
                | ttu.qos_level_fixed_l << 24
                // linux-lit: 28=HUBPREQ0_DCN_SURF0_TTU_CNTL0__QoS_RAMP_DISABLE__SHIFT
                | ttu.qos_ramp_disable_l << 28,
        )?;
        self.set(DCN_SURF0_TTU_CNTL1, ttu.refcyc_per_req_delivery_pre_l)
    }
    /// `hubp3_program_surface_config` for a linear RGB surface with no DCC, plus
    /// the primary surface address.
    fn program_surface(&mut self, surface: &Surface) -> Result<(), Error> {
        if surface.pitch == 0
            || surface.pitch < surface.viewport_width
            || surface.viewport_width == 0
            || surface.viewport_height == 0
        {
            return Err(Error::Invalid);
        }
        // The pipe can only address 48 bits, and a fetch starts on a request.
        if surface.address >= 1u64 << ADDRESS_BITS
            || surface.address % ADDRESS_ALIGN != 0
            || surface.address == 0
        {
            return Err(Error::Invalid);
        }
        // linux-lit: 0x7f=HUBP0_DCSURF_SURFACE_CONFIG__SURFACE_PIXEL_FORMAT_MASK
        self.update(DCSURF_SURFACE_CONFIG, 0x7f, pixel_format(surface.format))?;
        // Linear, with no meta surface and no pipe alignment to inherit.
        // linux-lit: 0x1f=HUBP0_DCSURF_TILING_CONFIG__SW_MODE_MASK
        self.update(DCSURF_TILING_CONFIG, 0x1f, SW_MODE_LINEAR)?;
        // The pitch register holds one less, and there is no meta pitch.
        self.set(DCSURF_SURFACE_PITCH, surface.pitch - 1)?;
        self.set(DCSURF_PRI_VIEWPORT_START, 0)?;
        self.set(
            DCSURF_PRI_VIEWPORT_DIMENSION,
            // linux-lit: 16=HUBP0_DCSURF_PRI_VIEWPORT_DIMENSION__PRI_VIEWPORT_HEIGHT__SHIFT
            surface.viewport_width | surface.viewport_height << 16,
        )?;
        // Not a trusted-memory surface, and no DCC to decompress.
        // linux-lit: 0x3=HUBPREQ0_DCSURF_SURFACE_CONTROL__PRIMARY_SURFACE_TMZ_MASK | HUBPREQ0_DCSURF_SURFACE_CONTROL__PRIMARY_SURFACE_DCC_EN_MASK
        self.update(DCSURF_SURFACE_CONTROL, 0x3, 0)?;
        self.set(
            DCSURF_PRIMARY_SURFACE_ADDRESS_HIGH,
            (surface.address >> 32) as u32,
        )?;
        // The low half last: writing it is what arms the new address.
        self.set(DCSURF_PRIMARY_SURFACE_ADDRESS, surface.address as u32)
    }
    /// `hubp2_vready_at_or_After_vsync`. The condition is the same one the DLG
    /// encoding already evaluated, so it is taken from there rather than
    /// recomputed from the timing and risking the two disagreeing.
    fn program_vready(&mut self, registers: &Registers) -> Result<(), Error> {
        let value = u32::from(registers.dlg.vready_after_vcount0 != 0);
        // linux-lit: 8=HUBP0_DCHUBP_CNTL__HUBP_VREADY_AT_OR_AFTER_VSYNC__SHIFT
        self.update(DCHUBP_CNTL, 1 << 8, value << 8)
    }
    /// `hubp2_set_blank_regs`. Blanking waits up to 100 ms for the pipe's
    /// outstanding requests to retire. Like Linux's REG_WAIT, an expired wait
    /// is logged (and counted) and the pipe is blanked anyway: a HUBP whose
    /// requests never drain (power-gated or hung GOP pipe at takeover) must
    /// not stop the sequence. A powered-down pipe reads back zero.
    async fn set_blank(&mut self, blank: bool) -> Result<(), Error> {
        if blank {
            let cntl = self.reg(DCHUBP_CNTL);
            let live = self.access(|io| io.read(cntl))?;
            if live == u32::MAX {
                return Err(Error::DeviceGone);
            }
            if live != 0 {
                let deadline = narf_time::Deadline::after_ms(100);
                loop {
                    let value = self.access(|io| io.read(cntl))?;
                    if value == u32::MAX {
                        return Err(Error::DeviceGone);
                    }
                    // linux-lit: 1=HUBP0_DCHUBP_CNTL__HUBP_NO_OUTSTANDING_REQ__SHIFT
                    if value & 1 << 1 != 0 {
                        break;
                    }
                    if deadline.expired() {
                        use core::fmt::Write;
                        self.blank_stalls = self.blank_stalls.saturating_add(1);
                        let _ = writeln!(
                            narf_console::Writer,
                            "amdgpu: hubp{} blank: outstanding requests did not retire (100 ms); blanking anyway",
                            self.instance
                        );
                        break;
                    }
                    delay(1).await;
                }
            }
        }
        // linux-lit: 12=HUBP0_DCHUBP_CNTL__HUBP_TTU_DISABLE__SHIFT
        self.update(DCHUBP_CNTL, 1 | 1 << 12, u32::from(blank))?;
        self.blanked = blank;
        Ok(())
    }
}

/// One owned DCN30/DCN314 hub pixel pipe.
#[derive(Debug)]
pub struct Hubp(Engine<Mmio>);
impl Hubp {
    /// # Safety
    /// Caller exclusively owns this HUBP instance for the object's lifetime,
    /// holds matching PCI authority and a permanent register mapping, and must
    /// keep the scanout memory it programs reserved until the pipe is blanked.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        instance: u8,
    ) -> Result<Self, Error> {
        let profile = Profile::resolve(gpu)?;
        if instance >= profile.pipes() {
            return Err(Error::Invalid);
        }
        let base = profile.bank(
            gpu,
            2, // linux-lit: 2=mmHUBP0_DCSURF_SURFACE_CONFIG_BASE_IDX
            // linux-ctx: reset
            (HUBPRET_CONTROL + u64::from(profile.pipes() - 1) * STRIDE) as u32,
        )?;
        Ok(Self(Engine {
            io: Mmio {
                regs: crate::amdgpu_reg_window::Window::new(gpu.regs),
                base,
            },
            authority,
            instance,
            blanked: true,
            profile,
            blank_stalls: 0,
        }))
    }
    pub fn instance(&self) -> u8 {
        self.0.instance
    }
    pub fn blanked(&self) -> bool {
        self.0.blanked
    }
    /// Blanks that proceeded after the outstanding-request wait expired.
    pub fn blank_stalls(&self) -> u32 {
        self.0.blank_stalls
    }
    /// Program the surface and the pacing that goes with it. The two belong
    /// together: deadlines derived for one surface do not hold for another.
    pub fn program(&mut self, surface: &Surface, registers: &Registers) -> Result<(), Error> {
        self.0.program_pacing(registers)?;
        self.0.program_vready(registers)?;
        self.0.program_surface(surface)
    }
    /// Blank the pipe, waiting (bounded, then logged) for its outstanding
    /// requests to retire.
    pub async fn blank(&mut self) -> Result<(), Error> {
        self.0.set_blank(true).await
    }
    pub async fn unblank(&mut self) -> Result<(), Error> {
        self.0.set_blank(false).await
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn_hubp_tests.rs"]
mod tests;
