//! DCN 3.1.4 hub pixel pipe. Programs the surface a pipe fetches and the
//! request, latency and throttle registers that pace that fetch. Offsets and
//! fields are `dcn_3_1_4_offset.h`/`dcn_3_1_4_sh_mask.h` at DCN base index 2;
//! sequencing follows Linux `dcn20_hubp.c` (`hubp2_program_requestor`,
//! `hubp2_program_deadline`, `hubp2_setup_interdependent`,
//! `hubp2_set_blank_regs`) and `dcn30_hubp.c::hubp3_program_surface_config`.
//!
//! The pacing values come from [`crate::amdgpu_dml_regs`], never from constants:
//! a HUBP programmed with someone else's deadlines underflows.
use crate::{
    amdgpu::AmdGpu, amdgpu_dcn_clk::Error, amdgpu_discovery as discovery, amdgpu_dml::Format,
    amdgpu_dml_regs::Registers,
};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

// HUBP block, stride 0xdc.
/// The DCN versions these offsets describe. Seventeen of the thirty registers
/// below move on DCN 3.5 (`dcn_3_5_0_offset.h`): the whole HUBPREQ pacing block
/// shifts down one dword, from `DCN_EXPANSION_MODE` 0x0629→0x0628 through
/// `REF_FREQ_TO_PIX_FREQ` 0x065d→0x065c, because 3.1.4's
/// `DCSURF_SURFACE_FLIP_INTERRUPT` is gone. A HUBP programmed with a
/// neighbouring generation's deadline ids underflows, so another generation
/// needs its own offset table, selected per version the way
/// `amdgpu_platform::SURFACE_WINDOWS` does it.
const DCN_VERSIONS: &[(u8, u8, u8)] = &[(3, 1, 4)];

const DCSURF_SURFACE_CONFIG: u64 = 0x05e5;
const DCSURF_TILING_CONFIG: u64 = 0x05e7;
const DCSURF_PRI_VIEWPORT_START: u64 = 0x05e9;
const DCSURF_PRI_VIEWPORT_DIMENSION: u64 = 0x05ea;
const DCHUBP_REQ_SIZE_CONFIG: u64 = 0x05f1;
const DCHUBP_REQ_SIZE_CONFIG_C: u64 = 0x05f2;
const DCHUBP_CNTL: u64 = 0x05f3;
// HUBPREQ block, same stride.
const DCSURF_SURFACE_PITCH: u64 = 0x0607;
const DCSURF_PRIMARY_SURFACE_ADDRESS: u64 = 0x060a;
const DCSURF_PRIMARY_SURFACE_ADDRESS_HIGH: u64 = 0x060b;
const DCSURF_SURFACE_CONTROL: u64 = 0x061a;
const DCN_EXPANSION_MODE: u64 = 0x0629;
const DCN_TTU_QOS_WM: u64 = 0x062a;
const DCN_GLOBAL_TTU_CNTL: u64 = 0x062b;
const DCN_SURF0_TTU_CNTL0: u64 = 0x062c;
const DCN_SURF0_TTU_CNTL1: u64 = 0x062d;
const BLANK_OFFSET_0: u64 = 0x0644;
const BLANK_OFFSET_1: u64 = 0x0645;
const DST_DIMENSIONS: u64 = 0x0646;
const DST_AFTER_SCALER: u64 = 0x0647;
const PREFETCH_SETTINGS: u64 = 0x0648;
const VBLANK_PARAMETERS_0: u64 = 0x064a;
const VBLANK_PARAMETERS_1: u64 = 0x064b;
const NOM_PARAMETERS_0: u64 = 0x0652;
const NOM_PARAMETERS_1: u64 = 0x0653;
const PER_LINE_DELIVERY_PRE: u64 = 0x065a;
const PER_LINE_DELIVERY: u64 = 0x065b;
const REF_FREQ_TO_PIX_FREQ: u64 = 0x065d;
// HUBPRET block, same stride.
const HUBPRET_CONTROL: u64 = 0x066c;
const STRIDE: u64 = 0xdc;
const LAST_REG: u32 = (HUBPRET_CONTROL + 3 * STRIDE) as u32;
const INSTANCES: u8 = 4;

/// `DC_SW_LINEAR`. No other swizzle is modelled by the mode math.
const SW_MODE_LINEAR: u32 = 0;
/// HUBP surface addresses are 48-bit and must land on a 256-byte request.
const ADDRESS_BITS: u32 = 48;
const ADDRESS_ALIGN: u64 = 256;

trait Io: Send {
    fn read(&mut self, reg: u64) -> u32;
    fn write(&mut self, reg: u64, value: u32);
}
#[derive(Debug)]
struct Mmio {
    regs: MmioRegion,
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
        Format::Rgb16 => 3,
        Format::Rgb32 => 8,
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
            0xfff << 4 | 0x3 << 20 | 0x3 << 22,
            // No second detile plane, and the RGB crossbar is straight through.
            3 << 22 | 2 << 20,
        )?;
        self.set(
            DCN_EXPANSION_MODE,
            rq.drq_expansion_mode
                | rq.crq_expansion_mode << 2
                | rq.mrq_expansion_mode << 4
                | rq.prq_expansion_mode << 6,
        )?;
        self.set(
            DCHUBP_REQ_SIZE_CONFIG,
            rq.swath_height
                | rq.pte_row_height_linear << 4
                | rq.chunk_size << 8
                | rq.min_chunk_size << 11
                | rq.meta_chunk_size << 14
                | rq.min_meta_chunk_size << 17
                | rq.dpte_group_size << 20
                | rq.mpte_group_size << 24,
        )?;
        // There is no chroma plane on this path.
        self.set(DCHUBP_REQ_SIZE_CONFIG_C, 0)?;

        self.set(
            BLANK_OFFSET_0,
            dlg.refcyc_h_blank_end | dlg.dlg_vblank_end << 16,
        )?;
        self.set(BLANK_OFFSET_1, dlg.min_dst_y_next_start)?;
        self.set(DST_DIMENSIONS, dlg.refcyc_per_htotal)?;
        self.set(
            DST_AFTER_SCALER,
            dlg.refcyc_x_after_scaler | dlg.dst_y_after_scaler << 16,
        )?;
        self.set(REF_FREQ_TO_PIX_FREQ, dlg.ref_freq_to_pix_freq)?;
        self.set(VBLANK_PARAMETERS_1, dlg.refcyc_per_pte_group_vblank_l)?;
        self.set(NOM_PARAMETERS_0, dlg.dst_y_per_pte_row_nom_l)?;
        self.set(NOM_PARAMETERS_1, dlg.refcyc_per_pte_group_nom_l)?;
        self.set(PER_LINE_DELIVERY, dlg.refcyc_per_line_delivery_l)?;
        self.set(
            PREFETCH_SETTINGS,
            dlg.vratio_prefetch | dlg.dst_y_prefetch << 24,
        )?;
        self.set(
            VBLANK_PARAMETERS_0,
            dlg.dst_y_per_vm_vblank | dlg.dst_y_per_row_vblank << 8,
        )?;
        self.set(PER_LINE_DELIVERY_PRE, dlg.refcyc_per_line_delivery_pre_l)?;

        self.set(
            DCN_TTU_QOS_WM,
            ttu.qos_level_low_wm | ttu.qos_level_high_wm << 16,
        )?;
        self.set(
            DCN_GLOBAL_TTU_CNTL,
            ttu.min_ttu_vblank | ttu.qos_level_flip << 28,
        )?;
        self.set(
            DCN_SURF0_TTU_CNTL0,
            ttu.refcyc_per_req_delivery_l
                | ttu.qos_level_fixed_l << 24
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
        self.update(DCSURF_SURFACE_CONFIG, 0x7f, pixel_format(surface.format))?;
        // Linear, with no meta surface and no pipe alignment to inherit.
        self.update(DCSURF_TILING_CONFIG, 0x1f, SW_MODE_LINEAR)?;
        // The pitch register holds one less, and there is no meta pitch.
        self.set(DCSURF_SURFACE_PITCH, surface.pitch - 1)?;
        self.set(DCSURF_PRI_VIEWPORT_START, 0)?;
        self.set(
            DCSURF_PRI_VIEWPORT_DIMENSION,
            surface.viewport_width | surface.viewport_height << 16,
        )?;
        // Not a trusted-memory surface, and no DCC to decompress.
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
        self.update(DCHUBP_CNTL, 1 << 8, value << 8)
    }
    /// `hubp2_set_blank_regs`. Blanking waits for the pipe's outstanding
    /// requests to retire, so scanout memory is not released while in flight.
    /// A powered-down pipe reads back zero and is already quiet.
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
                    if value & 1 << 1 != 0 {
                        break;
                    }
                    if deadline.expired() {
                        return Err(Error::Timeout);
                    }
                    delay(1).await;
                }
            }
        }
        self.update(DCHUBP_CNTL, 1 | 1 << 12, u32::from(blank))?;
        self.blanked = blank;
        Ok(())
    }
}

/// One owned DCN314 hub pixel pipe.
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
        if instance >= INSTANCES {
            return Err(Error::Invalid);
        }
        let base =
            crate::amdgpu_psp_ring::bank(gpu, discovery::HW_ID_DCN, DCN_VERSIONS, 2, LAST_REG)
                .map_err(|_| Error::Unsupported)?;
        Ok(Self(Engine {
            io: Mmio {
                regs: gpu.regs,
                base,
            },
            authority,
            instance,
            blanked: true,
        }))
    }
    pub fn instance(&self) -> u8 {
        self.0.instance
    }
    pub fn blanked(&self) -> bool {
        self.0.blanked
    }
    /// Program the surface and the pacing that goes with it. The two belong
    /// together: deadlines derived for one surface do not hold for another.
    pub fn program(&mut self, surface: &Surface, registers: &Registers) -> Result<(), Error> {
        self.0.program_pacing(registers)?;
        self.0.program_vready(registers)?;
        self.0.program_surface(surface)
    }
    /// Blank the pipe, waiting for its outstanding requests to retire.
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
