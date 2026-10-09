use super::*;
use crate::amdgpu_dml::{
    ClockState, Config, Memory, MemoryKind, Plane, Timing, DEFAULT_DENTIST_VCO_KHZ,
};
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Fake {
    values: Vec<u32>,
    writes: Vec<(u64, u32)>,
    gone: bool,
    /// Outstanding requests never retire, to exercise the blank timeout.
    stuck: bool,
}
impl Fake {
    fn new() -> Self {
        Self {
            values: vec![0; LAST_REG as usize + 1],
            writes: Vec::new(),
            gone: false,
            stuck: false,
        }
    }
}
impl Io for Fake {
    fn read(&mut self, reg: u64) -> u32 {
        if self.gone {
            return u32::MAX;
        }
        let value = self.values[reg as usize];
        // The pipe reports its requests retired unless held busy.
        if reg % STRIDE == DCHUBP_CNTL % STRIDE && !self.stuck {
            return value | 1 << 1;
        }
        value
    }
    fn write(&mut self, reg: u64, value: u32) {
        self.writes.push((reg, value));
        self.values[reg as usize] = value;
    }
}
fn engine(instance: u8) -> Engine<Fake> {
    Engine {
        io: Fake::new(),
        authority: Cap::bootstrap(),
        instance,
        blanked: true,
    }
}
fn timing() -> Timing {
    Timing {
        pixel_clock_khz: 148_500,
        h_active: 1920,
        h_total: 2200,
        h_front_porch: 88,
        h_sync_width: 44,
        v_active: 1080,
        v_total: 1125,
        v_front_porch: 4,
        v_sync_width: 5,
        h_sync_positive: true,
        v_sync_positive: true,
    }
}
fn config() -> Config {
    Config {
        timing: timing(),
        plane: Plane {
            format: Format::Rgb32,
            surface_width: 1920,
            surface_height: 1080,
            viewport_width: 1920,
            viewport_height: 1080,
            pitch: 1920,
            h_taps: 1,
            v_taps: 1,
        },
        dentist_vco_khz: DEFAULT_DENTIST_VCO_KHZ,
        cursors: 0,
    }
}
fn registers() -> Registers {
    let config = config();
    let geometry = config.geometry().unwrap();
    let clocks = ClockState {
        dcfclk_khz: 600_000,
        fclk_khz: 1_200_000,
        socclk_khz: 600_000,
        dispclk_khz: 151_579,
        dppclk_khz: 150_000,
        deep_sleep_dcfclk_khz: 10_674,
    };
    let memory = Memory {
        kind: MemoryKind::Ddr5,
        channels: 4,
        channel_width_bytes: 4,
        speed_mts: 5600,
    };
    let wm = config.watermarks(&memory, &clocks).unwrap();
    let prefetch = config.prefetch(&geometry, &clocks, &wm).unwrap();
    Registers::new(&config, &geometry, &clocks, &wm, &prefetch, 100_000).unwrap()
}
fn surface() -> Surface {
    Surface {
        address: 0x2_0010_0000,
        format: Format::Rgb32,
        pitch: 1920,
        viewport_width: 1920,
        viewport_height: 1080,
    }
}
fn run<T>(future: impl core::future::Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}

fn hubp_surface_programming_uses_the_owned_instance() -> TestResult {
    let mut hubp = engine(2);
    let regs = registers();
    if hubp.program_pacing(&regs).is_err() || hubp.program_surface(&surface()).is_err() {
        return TestResult::Fail("programming rejected");
    }
    let at = |reg: u64| reg + 2 * STRIDE;
    let v = &hubp.io.values;
    // ARGB8888 is format code 8, not its bit depth, and linear is swizzle zero.
    if v[at(DCSURF_SURFACE_CONFIG) as usize] & 0x7f != 8 {
        return TestResult::Fail("pixel format");
    }
    if v[at(DCSURF_TILING_CONFIG) as usize] & 0x1f != SW_MODE_LINEAR {
        return TestResult::Fail("tiling");
    }
    // The pitch register holds one less than the pitch.
    if v[at(DCSURF_SURFACE_PITCH) as usize] != 1919 {
        return TestResult::Fail("pitch");
    }
    if v[at(DCSURF_PRI_VIEWPORT_DIMENSION) as usize] != 1920 | 1080 << 16
        || v[at(DCSURF_PRI_VIEWPORT_START) as usize] != 0
    {
        return TestResult::Fail("viewport");
    }
    if v[at(DCSURF_PRIMARY_SURFACE_ADDRESS) as usize] != 0x0010_0000
        || v[at(DCSURF_PRIMARY_SURFACE_ADDRESS_HIGH) as usize] != 2
    {
        return TestResult::Fail("surface address");
    }
    // The low half must be written last, since that is what arms the address.
    let high_at = hubp
        .io
        .writes
        .iter()
        .rposition(|(r, _)| *r == at(DCSURF_PRIMARY_SURFACE_ADDRESS_HIGH));
    let low_at = hubp
        .io
        .writes
        .iter()
        .rposition(|(r, _)| *r == at(DCSURF_PRIMARY_SURFACE_ADDRESS));
    if high_at >= low_at {
        return TestResult::Fail("address armed before its high half");
    }
    // Neither trusted memory nor DCC.
    if v[at(DCSURF_SURFACE_CONTROL) as usize] & 3 != 0 {
        return TestResult::Fail("surface control");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-hubp",
    hubp_surface_programming_uses_the_owned_instance
);

fn hubp_rejects_surfaces_the_pipe_cannot_fetch() -> TestResult {
    let mut hubp = engine(0);
    for bad in [
        // Not on a 256-byte request boundary.
        Surface {
            address: 0x2_0010_0010,
            ..surface()
        },
        // Beyond the pipe's 48-bit addressing.
        Surface {
            address: 1 << 48,
            ..surface()
        },
        // A null address would fetch from the start of VRAM.
        Surface {
            address: 0,
            ..surface()
        },
        // A surface narrower than its viewport would fetch past each line.
        Surface {
            pitch: 1000,
            ..surface()
        },
        Surface {
            pitch: 0,
            ..surface()
        },
        Surface {
            viewport_height: 0,
            ..surface()
        },
    ] {
        if hubp.program_surface(&bad) != Err(Error::Invalid) {
            return TestResult::Fail("unfetchable surface accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-hubp",
    hubp_rejects_surfaces_the_pipe_cannot_fetch
);

fn hubp_pacing_registers_carry_the_derived_deadlines() -> TestResult {
    let mut hubp = engine(0);
    let regs = registers();
    // Seed the two HUBPRET_CONTROL bits this path must not disturb:
    // PACK_3TO2_ELEMENT_DISABLE 0x00008000, which no DCN hubp code in Linux
    // writes, and CROSSBAR_SRC_ALPHA 0x00030000 / CROSSBAR_SRC_Y_G 0x000C0000,
    // which `hubp2_program_pixel_format` leaves alone (it is a REG_UPDATE_2
    // over CB_B and CR_R only).
    hubp.io.values[HUBPRET_CONTROL as usize] = 0x0000_8000 | 0x0004_0000;
    if hubp.program_pacing(&regs).is_err() {
        return TestResult::Fail("pacing rejected");
    }
    let pret = hubp.io.values[HUBPRET_CONTROL as usize];
    if pret & 0x0000_8000 == 0 {
        return TestResult::Fail("PACK_3TO2_ELEMENT_DISABLE is not ours to clear");
    }
    if pret & 0x0003_0000 != 0x0000_0000 || pret & 0x000C_0000 != 0x0004_0000 {
        return TestResult::Fail("the alpha and Y/G crossbar fields must survive");
    }
    // regHUBPRET0_HUBPRET_CONTROL__DET_BUF_PLANE1_BASE_ADDRESS_MASK is
    // 0x00001FF0 — nine bits at 4, not twelve. There is no second detile plane
    // on this path, so the field lands zero.
    if pret & 0x0000_1FF0 != 0 {
        return TestResult::Fail("no second detile plane means a zero base address");
    }
    // CROSSBAR_SRC_CR_R 0x00C00000 = 3 and CROSSBAR_SRC_CB_B 0x00300000 = 2 —
    // `red_bar`/`blue_bar` for a non-byte-swapped A*GB surface.
    if (pret & 0x00C0_0000) >> 22 != 3 || (pret & 0x0030_0000) >> 20 != 2 {
        return TestResult::Fail("the RGB crossbar is not straight through");
    }
    let v = &hubp.io.values;
    // Request sizes. The shifts are the ones `dcn_3_1_4_sh_mask.h` gives, not
    // the ones this module carries: SWATH_HEIGHT 0x00000007,
    // PTE_ROW_HEIGHT_LINEAR 0x00000070, CHUNK_SIZE 0x00000700, MIN_CHUNK_SIZE
    // 0x00001800, META_CHUNK_SIZE 0x00030000, MIN_META_CHUNK_SIZE 0x000C0000,
    // DPTE_GROUP_SIZE 0x00700000, VM_GROUP_SIZE 0x07000000. Note the three
    // unused bits between MIN_CHUNK_SIZE and META_CHUNK_SIZE — the run is not
    // evenly spaced, which is what the old expectation assumed.
    let req = v[DCHUBP_REQ_SIZE_CONFIG as usize];
    let field = |mask: u32| (req & mask) >> mask.trailing_zeros();
    for (mask, want, name) in [
        (0x0000_0007u32, regs.rq.swath_height, "SWATH_HEIGHT"),
        (
            0x0000_0070,
            regs.rq.pte_row_height_linear,
            "PTE_ROW_HEIGHT_LINEAR",
        ),
        (0x0000_0700, regs.rq.chunk_size, "CHUNK_SIZE"),
        (0x0000_1800, regs.rq.min_chunk_size, "MIN_CHUNK_SIZE"),
        (0x0003_0000, regs.rq.meta_chunk_size, "META_CHUNK_SIZE"),
        (
            0x000C_0000,
            regs.rq.min_meta_chunk_size,
            "MIN_META_CHUNK_SIZE",
        ),
        (0x0070_0000, regs.rq.dpte_group_size, "DPTE_GROUP_SIZE"),
        (0x0700_0000, regs.rq.mpte_group_size, "VM_GROUP_SIZE"),
    ] {
        if field(mask) != want {
            let _ = name;
            return TestResult::Fail("request size config field in the wrong place");
        }
    }
    // Nothing may land outside the eight fields: bits 15:13, 19, 23 and 31:27
    // are reserved, and the old shifts put META_CHUNK_SIZE's value in 15:14.
    let defined = 0x0000_0007u32
        | 0x0000_0070
        | 0x0000_0700
        | 0x0000_1800
        | 0x0003_0000
        | 0x000C_0000
        | 0x0070_0000
        | 0x0700_0000;
    if req & !defined != 0 {
        return TestResult::Fail("request size config wrote a reserved bit");
    }
    // The two meta fields are the ones that were misplaced, and both are
    // non-zero here, so a wrong shift is visible rather than latent.
    if regs.rq.meta_chunk_size == 0 || regs.rq.min_meta_chunk_size == 0 {
        return TestResult::Fail("this fixture must exercise the meta fields");
    }
    // Expansion modes are not in the order the fields are named.
    if v[DCN_EXPANSION_MODE as usize]
        != regs.rq.drq_expansion_mode
            | regs.rq.crq_expansion_mode << 2
            | regs.rq.mrq_expansion_mode << 4
            | regs.rq.prq_expansion_mode << 6
    {
        return TestResult::Fail("expansion modes");
    }
    // There is no chroma plane, so its request sizes must be cleared, not left
    // behind for a previous owner's plane to keep fetching against.
    if v[DCHUBP_REQ_SIZE_CONFIG_C as usize] != 0 {
        return TestResult::Fail("chroma request sizes retained");
    }
    // Deadlines, with the prefetch budget in the high byte.
    if v[PREFETCH_SETTINGS as usize] != regs.dlg.vratio_prefetch | regs.dlg.dst_y_prefetch << 24 {
        return TestResult::Fail("prefetch settings");
    }
    if v[VBLANK_PARAMETERS_0 as usize]
        != regs.dlg.dst_y_per_vm_vblank | regs.dlg.dst_y_per_row_vblank << 8
    {
        return TestResult::Fail("vblank parameters");
    }
    if v[BLANK_OFFSET_0 as usize] != regs.dlg.refcyc_h_blank_end | regs.dlg.dlg_vblank_end << 16 {
        return TestResult::Fail("blank offsets");
    }
    if v[DST_AFTER_SCALER as usize]
        != regs.dlg.refcyc_x_after_scaler | regs.dlg.dst_y_after_scaler << 16
    {
        return TestResult::Fail("after-scaler delay");
    }
    if v[REF_FREQ_TO_PIX_FREQ as usize] != regs.dlg.ref_freq_to_pix_freq {
        return TestResult::Fail("reference clock ratio");
    }
    // Throttle thresholds.
    if v[DCN_GLOBAL_TTU_CNTL as usize] != regs.ttu.min_ttu_vblank | regs.ttu.qos_level_flip << 28 {
        return TestResult::Fail("global TTU");
    }
    if v[DCN_SURF0_TTU_CNTL0 as usize]
        != regs.ttu.refcyc_per_req_delivery_l
            | regs.ttu.qos_level_fixed_l << 24
            | regs.ttu.qos_ramp_disable_l << 28
    {
        return TestResult::Fail("surface TTU");
    }
    if v[DCN_SURF0_TTU_CNTL1 as usize] != regs.ttu.refcyc_per_req_delivery_pre_l {
        return TestResult::Fail("prefetch request delivery");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-hubp",
    hubp_pacing_registers_carry_the_derived_deadlines
);

fn hubp_blank_waits_for_outstanding_requests() -> TestResult {
    let mut hubp = engine(1);
    hubp.program_pacing(&registers()).unwrap();
    hubp.program_surface(&surface()).unwrap();
    if run(hubp.set_blank(false)).is_err() || hubp.blanked {
        return TestResult::Fail("unblank rejected");
    }
    if hubp.io.values[(DCHUBP_CNTL + STRIDE) as usize] & 1 != 0 {
        return TestResult::Fail("pipe left blanked");
    }
    if run(hubp.set_blank(true)).is_err() || !hubp.blanked {
        return TestResult::Fail("blank rejected");
    }
    if hubp.io.values[(DCHUBP_CNTL + STRIDE) as usize] & 1 != 1 {
        return TestResult::Fail("pipe not blanked");
    }
    // A pipe whose requests never retire must time out rather than be called
    // blanked while a fetch is still in flight against scanout memory.
    let mut stuck = engine(1);
    stuck.io.values[(DCHUBP_CNTL + STRIDE) as usize] = 1 << 12;
    stuck.io.stuck = true;
    // Start from a running pipe, so the state after a failed blank is the
    // failure's doing rather than the initial condition.
    stuck.blanked = false;
    if run(stuck.set_blank(true)) != Err(Error::Timeout) {
        return TestResult::Fail("in-flight pipe reported as blanked");
    }
    if stuck.blanked {
        return TestResult::Fail("in-flight pipe marked blanked");
    }
    if stuck.io.values[(DCHUBP_CNTL + STRIDE) as usize] & 1 != 0 {
        return TestResult::Fail("blank bit set while a fetch was in flight");
    }
    // A powered-down pipe reads back zero and needs no wait at all.
    let mut gated = engine(1);
    gated.io.stuck = true;
    gated.io.values[(DCHUBP_CNTL + STRIDE) as usize] = 0;
    if run(gated.set_blank(true)).is_err() {
        return TestResult::Fail("power-gated pipe timed out");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-hubp",
    hubp_blank_waits_for_outstanding_requests
);
