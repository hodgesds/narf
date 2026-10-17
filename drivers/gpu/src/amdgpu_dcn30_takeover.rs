//! Taking DCN3.0 over from the GOP: the part of Linux `dcn30_init_hw` that
//! runs before the first native modeset and retires whatever the firmware
//! left lit, in Linux's order.
//!
//! On a cold UEFI boot of this card the PSP SOS is not alive, so no mode1
//! reset runs and the GOP's stream (OTG, OPP, HUBP fetching the GOP surface,
//! DIG and PHY) is still live. Linux does not refuse that state; with no
//! seamless boot it powers it down:
//!
//! 1. `dccg2_init`, `dcn10_bios_golden_init` and `dcn20_disable_vga` (the
//!    caller runs the first two; VGA is cleared here).
//! 2. `enc3_hw_init` per link: `TMDS_CTL_BITS.TMDS_CTL0` (the AUX half is the
//!    DDC owner's `dcn10_aux_initialize`).
//! 3. `dcn20_enable_power_gating_plane(true)`: every plane domain's
//!    POWER_FORCEON cleared under `DC_IP_REQUEST_CNTL`.
//! 4. `dcn10_init_pipes`: every running OTG blanked through its OPP's pattern
//!    generator (`dcn20_init_blank`, `dcn20_wait_for_blank_complete`) and
//!    locked; every MPCC reset (`mpc3_mpc_init_single_inst`); each pipe
//!    unlocked, its plane disabled (`dcn20_plane_atomic_disable`: MPCC idle,
//!    HUBP blank, HUBP and DPP clocks off, `dcn10_plane_atomic_power_down`
//!    with pipe 5's domains left on as `dcn20_{dpp,hubp}_pg_control` require)
//!    and `optc3_tg_init`.
//! 5. `dce110_power_down` when any DIG backend is enabled:
//!    `power_down_encoders` (DP streams blanked, VBIOS transmitter DISABLE
//!    with `SIGNAL_TYPE_NONE`), then `power_down_controllers` (every OTG's
//!    `optc1_disable_crtc`). `power_down_clock_sources` is a no-op on DCN:
//!    `set_pixel_clock_v7` rejects `CONTROLLER_ID_UNDEFINED`.
//!
//! `link_blank_all_dp_displays` is not repeated: at `init_hw` no link has a
//! local sink yet, so Linux skips every link there.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_dcn_clk::Error as BlockError,
    amdgpu_dcn_hubp::Hubp,
    amdgpu_dcn_otg::Otg,
    amdgpu_dcn_plane::Opp,
    amdgpu_navi22_bios::{Tables, Transmitter, TransmitterAction, TransmitterMode},
    amdgpu_navi22_display::{Connector, Signal},
    amdgpu_navi22_modeset::{Error, PIPES, STREAMS},
    amdgpu_reg_window::Window,
};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, CapError, CapOp, Write};

// linux-ctx: hdr=dcn seg=1
// DCN base index 1 (dcn_3_0_0_offset.h).
// linux: mmD1VGA_CONTROL; mmD2VGA_CONTROL; mmD3VGA_CONTROL; mmD4VGA_CONTROL; mmD5VGA_CONTROL
// linux: mmD6VGA_CONTROL
const D_VGA_CONTROL: [u64; 6] = [0x000c, 0x000e, 0x0038, 0x0039, 0x003a, 0x003b];
// linux-ctx: hdr=dcn seg=2
// DCN base index 2.
const DOMAIN0_PG_CONFIG: u64 = 0x0080; // linux: mmDOMAIN0_PG_CONFIG
/// DOMAIN0..11 (HUBP/DPP) and DOMAIN16..21 (DSC).
const PLANE_DOMAINS: core::ops::Range<u64> = 0..12;
const DSC_DOMAIN16_PG_CONFIG: u64 = 0x00a1; // linux: mmDOMAIN16_PG_CONFIG
const DOMAIN_POWER_FORCEON: u32 = 1 << 0; // linux: DOMAIN0_PG_CONFIG__DOMAIN0_POWER_FORCEON_MASK
const DOMAIN_POWER_GATE: u32 = 1 << 8; // linux: DOMAIN0_PG_CONFIG__DOMAIN0_POWER_GATE_MASK
                                       // linux: DOMAIN0_PG_STATUS__DOMAIN0_PGFSM_PWR_STATUS_MASK
const DOMAIN_PGFSM_PWR_STATUS: u32 = 0xc000_0000;
const DC_IP_REQUEST_CNTL: u64 = 0x00b2; // linux: mmDC_IP_REQUEST_CNTL
const IP_REQUEST_EN: u32 = 1 << 0; // linux: DC_IP_REQUEST_CNTL__IP_REQUEST_EN_MASK
const DPP_CONTROL: u64 = 0x0cc5; // linux: mmDPP_TOP0_DPP_CONTROL
const DPP_STRIDE: u64 = 0x16b; // linux: mmDPP_TOP1_DPP_CONTROL - mmDPP_TOP0_DPP_CONTROL
const DPP_CLOCK_ENABLE: u32 = 1 << 4; // linux: DPP_TOP0_DPP_CONTROL__DPP_CLOCK_ENABLE_MASK
const HUBP_CLK_CNTL: u64 = 0x05f4; // linux: mmHUBP0_HUBP_CLK_CNTL
const HUBP_STRIDE: u64 = 0xdc; // linux: mmHUBP1_HUBP_CLK_CNTL - mmHUBP0_HUBP_CLK_CNTL
const HUBP_CLOCK_ENABLE: u32 = 1 << 0; // linux: HUBP0_HUBP_CLK_CNTL__HUBP_CLOCK_ENABLE_MASK
const DPG_CONTROL: u64 = 0x1854; // linux: mmDPG0_DPG_CONTROL
const DPG_DIMENSIONS: u64 = 0x1856; // linux: mmDPG0_DPG_DIMENSIONS
const DPG_STATUS: u64 = 0x185b; // linux: mmDPG0_DPG_STATUS
const DPG_STRIDE: u64 = 0x5a; // linux: mmDPG1_DPG_CONTROL - mmDPG0_DPG_CONTROL
const DPG_EN: u32 = 1 << 0; // linux: DPG0_DPG_CONTROL__DPG_EN_MASK
                            // linux: DPG0_DPG_STATUS__DPG_DOUBLE_BUFFER_PENDING_MASK
const DPG_DOUBLE_BUFFER_PENDING: u32 = 1 << 0;
const ODM_DATA_SOURCE_SELECT: u64 = 0x1acb; // linux: mmODM0_OPTC_DATA_SOURCE_SELECT
const ODM_INPUT_GLOBAL_CONTROL: u64 = 0x1aca; // linux: mmODM0_OPTC_INPUT_GLOBAL_CONTROL
                                              // linux: mmODM1_OPTC_DATA_SOURCE_SELECT - mmODM0_OPTC_DATA_SOURCE_SELECT
const ODM_STRIDE: u64 = 0x10;
// linux: ODM0_OPTC_DATA_SOURCE_SELECT__OPTC_SEG0_SRC_SEL_MASK
const OPTC_SEG0_SRC_SEL: u32 = 0x0000_0f00;
// linux: ODM0_OPTC_INPUT_GLOBAL_CONTROL__OPTC_UNDERFLOW_CLEAR_MASK
const OPTC_UNDERFLOW_CLEAR: u32 = 0x1000;
const OTG_STRIDE: u64 = 0x80; // linux: mmOTG1_OTG_CONTROL - mmOTG0_OTG_CONTROL
const OTG_H_BLANK_START_END: u64 = 0x1b2b; // linux: mmOTG0_OTG_H_BLANK_START_END
const OTG_V_BLANK_START_END: u64 = 0x1b36; // linux: mmOTG0_OTG_V_BLANK_START_END
const OTG_CONTROL: u64 = 0x1b41; // linux: mmOTG0_OTG_CONTROL
const OTG_MASTER_EN: u32 = 1 << 0; // linux: OTG0_OTG_CONTROL__OTG_MASTER_EN_MASK
const OTG_DOUBLE_BUFFER_CONTROL: u64 = 0x1b5b; // linux: mmOTG0_OTG_DOUBLE_BUFFER_CONTROL
                                               // linux: OTG0_OTG_DOUBLE_BUFFER_CONTROL__OTG_DRR_TIMING_DBUF_UPDATE_MODE_MASK
const OTG_DRR_TIMING_DBUF_UPDATE_MODE: u32 = 0x0300_0000;
const OTG_MASTER_UPDATE_LOCK: u64 = 0x1b8b; // linux: mmOTG0_OTG_MASTER_UPDATE_LOCK
const OTG_GLOBAL_CONTROL2: u64 = 0x1b92; // linux: mmOTG0_OTG_GLOBAL_CONTROL2
                                         // linux: OTG0_OTG_GLOBAL_CONTROL2__OTG_MASTER_UPDATE_LOCK_SEL_MASK
const OTG_MASTER_UPDATE_LOCK_SEL: u32 = 0x0e00_0000;
// linux: OTG0_OTG_MASTER_UPDATE_LOCK__UPDATE_LOCK_STATUS_MASK
const UPDATE_LOCK_STATUS: u32 = 1 << 8;
const DIG_STRIDE: u64 = 0x100; // linux: mmDIG1_DIG_BE_CNTL - mmDIG0_DIG_BE_CNTL
const DIG_BE_CNTL: u64 = 0x20b0; // linux: mmDIG0_DIG_BE_CNTL
const DIG_BE_EN_CNTL: u64 = 0x20b1; // linux: mmDIG0_DIG_BE_EN_CNTL
const DIG_ENABLE: u32 = 1 << 0; // linux: DIG0_DIG_BE_EN_CNTL__DIG_ENABLE_MASK
const DIG_MODE: u32 = 0x0007_0000; // linux: DIG0_DIG_BE_CNTL__DIG_MODE_MASK
const DIG_FE_SOURCE_SELECT: u32 = 0x7f00; // linux: DIG0_DIG_BE_CNTL__DIG_FE_SOURCE_SELECT_MASK
const TMDS_CTL_BITS: u64 = 0x20de; // linux: mmDIG0_TMDS_CTL_BITS
const TMDS_CTL0: u32 = 1 << 0; // linux: DIG0_TMDS_CTL_BITS__TMDS_CTL0_MASK
const DP_VID_STREAM_CNTL: u64 = 0x210c; // linux: mmDP0_DP_VID_STREAM_CNTL
                                        // linux-ctx: hdr=dcn seg=3
                                        // DCN base index 3: MPCC instances stride 0x20, MPC_OUTn_MUX stride 4.
const MPCC_TOP_SEL: u64 = 0x0000; // linux: mmMPCC0_MPCC_TOP_SEL
const MPCC_BOT_SEL: u64 = 0x0001; // linux: mmMPCC0_MPCC_BOT_SEL
const MPCC_OPP_ID: u64 = 0x0002; // linux: mmMPCC0_MPCC_OPP_ID
const MPCC_UPDATE_LOCK_SEL: u64 = 0x0005; // linux: mmMPCC0_MPCC_UPDATE_LOCK_SEL
const MPCC_STATUS: u64 = 0x000d; // linux: mmMPCC0_MPCC_STATUS
const MPCC_STRIDE: u64 = 0x20; // linux: mmMPCC1_MPCC_TOP_SEL - mmMPCC0_MPCC_TOP_SEL
const MPCC_IDLE: u32 = 1 << 0; // linux: MPCC0_MPCC_STATUS__MPCC_IDLE_MASK
const MPC_OUT_MUX: u64 = 0x0580; // linux: mmMPC_OUT0_MUX
const MPC_OUT_STRIDE: u64 = 4; // linux: mmMPC_OUT1_MUX - mmMPC_OUT0_MUX
const MPC_OUT_MUX_SEL: u32 = 0xf; // linux: MPC_OUT0_MUX__MPC_OUT_MUX_MASK
                                  // linux: MPC_OUT0_MUX__MPC_OUT_RATE_CONTROL_DISABLE_MASK
const MPC_OUT_RATE_CONTROL_DISABLE: u32 = 1 << 8;
// linux: MPC_OUT0_MUX__MPC_OUT_FLOW_CONTROL_COUNT_MASK
const MPC_OUT_FLOW_CONTROL_COUNT: u32 = 0x007f_f800;
// linux-ctx: reset
/// The last dwords this module touches per bank, for the bounds.
pub(crate) const LAST_DCN1: u32 = 0x003b; // linux: mmD6VGA_CONTROL
                                          // linux: n/a (NARF bank bound)
pub(crate) const LAST_DCN2: u32 = (TMDS_CTL_BITS + 5 * DIG_STRIDE) as u32;
// linux: n/a (NARF bank bound)
pub(crate) const LAST_DCN3: u32 = (MPC_OUT_MUX + 5 * MPC_OUT_STRIDE) as u32;

struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
async fn sleep_us(us: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant()).await;
}

/// Raw access to the DCN banks the display owners share, by byte offset.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Regs {
    pub(crate) window: Window,
    pub(crate) authority: Cap<BusDeviceCap, Write>,
}
impl Regs {
    pub(crate) fn read(&mut self, offset: u64) -> Result<u32, Error> {
        let window = self.window;
        // SAFETY: callers pass offsets inside banks bounded by discovery.
        let value = self
            .authority
            .invoke(Op(|| unsafe { window.read32(offset) }))
            .map_err(|_| Error::Block(BlockError::Revoked))?;
        if value == u32::MAX {
            return Err(Error::Block(BlockError::DeviceGone));
        }
        Ok(value)
    }
    pub(crate) fn write(&mut self, offset: u64, value: u32) -> Result<(), Error> {
        let window = self.window;
        // SAFETY: as `read`.
        self.authority
            .invoke(Op(|| unsafe { window.write32(offset, value) }))
            .map_err(|_| Error::Block(BlockError::Revoked))
    }
    pub(crate) fn update(&mut self, offset: u64, mask: u32, value: u32) -> Result<(), Error> {
        let old = self.read(offset)?;
        self.write(offset, (old & !mask) | (value & mask))
    }
    /// Linux `REG_WAIT`: `tries` reads `interval_us` apart for `mask` to
    /// read `want`. Returns whether it did; a timeout is the caller's call.
    pub(crate) async fn wait(
        &mut self,
        offset: u64,
        mask: u32,
        want: u32,
        interval_us: u64,
        tries: u32,
    ) -> Result<bool, Error> {
        for _ in 0..tries {
            if self.read(offset)? & mask == want & mask {
                return Ok(true);
            }
            sleep_us(interval_us).await;
        }
        Ok(false)
    }
}

/// What the firmware had left running.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Inherited {
    /// OTGs with `OTG_MASTER_EN` set on entry.
    pub otgs: u8,
    /// DIG backends with `DIG_ENABLE` set on entry.
    pub digs: u8,
}

/// The DCN banks and owners this pass reaches, all six pipes and links.
pub(crate) struct Takeover<'a> {
    pub(crate) gpu: &'a AmdGpu,
    pub(crate) regs: Regs,
    pub(crate) dcn1: u64,
    pub(crate) dcn2: u64,
    pub(crate) dcn3: u64,
}
impl Takeover<'_> {
    fn d2(&self, reg: u64) -> u64 {
        self.dcn2 + reg * 4
    }
    fn d3(&self, reg: u64) -> u64 {
        self.dcn3 + reg * 4
    }
    /// `dcn20_disable_vga`.
    pub(crate) fn disable_vga(&mut self) -> Result<(), Error> {
        for reg in D_VGA_CONTROL {
            self.regs.write(self.dcn1 + reg * 4, 0)?;
        }
        Ok(())
    }
    /// The register half of `enc3_hw_init` for one link encoder.
    pub(crate) fn link_hw_init(&mut self, transmitter: u8) -> Result<(), Error> {
        if transmitter >= STREAMS {
            return Err(Error::Invalid);
        }
        let reg = self.d2(TMDS_CTL_BITS + u64::from(transmitter) * DIG_STRIDE);
        self.regs.update(reg, TMDS_CTL0, TMDS_CTL0)
    }
    /// `dcn20_enable_power_gating_plane(true)`.
    fn enable_power_gating_plane(&mut self) -> Result<(), Error> {
        let request = self.d2(DC_IP_REQUEST_CNTL);
        let original = self.regs.read(request)? & IP_REQUEST_EN;
        if original == 0 {
            self.regs.write(request, IP_REQUEST_EN)?;
        }
        // HUBP 0,2..10 then DPP 1,3..11, then the six DSC domains.
        for domain in PLANE_DOMAINS
            .step_by(2)
            .chain(PLANE_DOMAINS.skip(1).step_by(2))
        {
            // linux-lit: 2=mmDOMAIN1_PG_CONFIG - mmDOMAIN0_PG_CONFIG
            let reg = self.d2(DOMAIN0_PG_CONFIG + 2 * domain);
            self.regs.update(reg, DOMAIN_POWER_FORCEON, 0)?;
        }
        // linux: n/a (DOMAIN16..21: dcn20_enable_power_gating_plane's six DSC domains)
        for dsc in 0..6 {
            // linux-lit: 2=mmDOMAIN17_PG_CONFIG - mmDOMAIN16_PG_CONFIG
            let reg = self.d2(DSC_DOMAIN16_PG_CONFIG + 2 * dsc);
            self.regs.update(reg, DOMAIN_POWER_FORCEON, 0)?;
        }
        if original == 0 {
            self.regs.write(request, 0)?;
        }
        Ok(())
    }
    fn otg(&self, reg: u64, pipe: u8) -> u64 {
        self.d2(reg + u64::from(pipe) * OTG_STRIDE)
    }
    fn otg_enabled(&mut self, pipe: u8) -> Result<bool, Error> {
        Ok(self.regs.read(self.otg(OTG_CONTROL, pipe))? & OTG_MASTER_EN != 0)
    }
    /// `optc3_lock`; a status timeout only logs in Linux.
    async fn lock(&mut self, pipe: u8, lock: bool) -> Result<(), Error> {
        if !lock {
            return self.regs.write(self.otg(OTG_MASTER_UPDATE_LOCK, pipe), 0);
        }
        self.regs.update(
            self.otg(OTG_GLOBAL_CONTROL2, pipe),
            OTG_MASTER_UPDATE_LOCK_SEL,
            u32::from(pipe) << OTG_MASTER_UPDATE_LOCK_SEL.trailing_zeros(),
        )?;
        let reg = self.otg(OTG_MASTER_UPDATE_LOCK, pipe);
        self.regs.write(reg, 1)?;
        self.regs
            .wait(reg, UPDATE_LOCK_STATUS, UPDATE_LOCK_STATUS, 1, 10)
            .await?;
        Ok(())
    }
    /// `dcn20_init_blank` + `dcn20_wait_for_blank_complete` for one running
    /// OTG: black through the OPP feeding segment 0, over the OTG's active
    /// size (`optc1_get_otg_active_size`).
    async fn init_blank(&mut self, pipe: u8) -> Result<(), Error> {
        let source = self
            .regs
            .read(self.d2(ODM_DATA_SOURCE_SELECT + u64::from(pipe) * ODM_STRIDE))?;
        let opp = ((source & OPTC_SEG0_SRC_SEL) >> OPTC_SEG0_SRC_SEL.trailing_zeros()) as u8;
        if opp >= PIPES {
            // Linux asserts and leaves this OTG unblanked.
            return Ok(());
        }
        let control = self.d2(DPG_CONTROL + u64::from(opp) * DPG_STRIDE);
        let status = self.d2(DPG_STATUS + u64::from(opp) * DPG_STRIDE);
        // opp2_dpg_is_blanked: already black, leave it.
        if self.regs.read(control)? & DPG_EN != 0
            && self.regs.read(status)? & DPG_DOUBLE_BUFFER_PENDING == 0
        {
            return Ok(());
        }
        let h = self.regs.read(self.otg(OTG_H_BLANK_START_END, pipe))?;
        let v = self.regs.read(self.otg(OTG_V_BLANK_START_END, pipe))?;
        // linux-lit: 0x7fff=OTG0_OTG_H_BLANK_START_END__OTG_H_BLANK_START_MASK
        // linux-lit: 16=OTG0_OTG_H_BLANK_START_END__OTG_H_BLANK_END__SHIFT
        let width = (h & 0x7fff).saturating_sub((h >> 16) & 0x7fff);
        // linux-lit: 0x7fff=OTG0_OTG_V_BLANK_START_END__OTG_V_BLANK_START_MASK
        // linux-lit: 16=OTG0_OTG_V_BLANK_START_END__OTG_V_BLANK_END__SHIFT
        let height = (v & 0x7fff).saturating_sub((v >> 16) & 0x7fff);
        self.regs.write(
            self.d2(DPG_DIMENSIONS + u64::from(opp) * DPG_STRIDE),
            height | width << 16, // linux-lit: 16=DPG0_DPG_DIMENSIONS__DPG_ACTIVE_WIDTH__SHIFT
        )?;
        // SAFETY: the takeover holds the whole display engine.
        let mut owner = unsafe { Opp::new(self.gpu, self.regs.authority, opp) }?;
        owner.set_blank(true)?;
        // 1000 x 100 us for the pattern to latch; Linux logs a timeout.
        self.regs
            .wait(status, DPG_DOUBLE_BUFFER_PENDING, 0, 100, 1000)
            .await?;
        Ok(())
    }
    /// `mpc3_mpc_init_single_inst`.
    fn mpc_init(&mut self, mpcc: u8) -> Result<(), Error> {
        let base = u64::from(mpcc) * MPCC_STRIDE;
        // linux-lit: 0xf=MPCC0_MPCC_OPP_ID__MPCC_OPP_ID_MASK
        let opp = self.regs.read(self.d3(MPCC_OPP_ID + base))? & 0xf;
        for reg in [
            MPCC_TOP_SEL,
            MPCC_BOT_SEL,
            MPCC_OPP_ID,
            MPCC_UPDATE_LOCK_SEL,
        ] {
            // linux: n/a (literal 0xf in dcn10_mpc.c:mpc1_mpc_init_single_inst)
            self.regs.write(self.d3(reg + base), 0xf)?;
        }
        if opp < u32::from(PIPES) {
            let mux = self.d3(MPC_OUT_MUX + u64::from(opp) * MPC_OUT_STRIDE);
            // linux: n/a (literal 0xf in dcn10_mpc.c:mpc1_mpc_init_single_inst)
            self.regs.update(mux, MPC_OUT_MUX_SEL, 0xf)?;
        }
        let mux = self.d3(MPC_OUT_MUX + u64::from(mpcc) * MPC_OUT_STRIDE);
        self.regs.update(
            mux,
            MPC_OUT_RATE_CONTROL_DISABLE | MPC_OUT_FLOW_CONTROL_COUNT,
            MPC_OUT_RATE_CONTROL_DISABLE,
        )
    }
    /// `dcn20_dpp_pg_control`/`dcn20_hubp_pg_control(false)`: gate one
    /// domain and wait (1000 x 1 us) for PGFSM to report it off. Pipe 5's
    /// domains are never gated (power gating on pipe 5 is de-featured and
    /// may hard-reset the GPU).
    async fn gate(&mut self, domain: u64) -> Result<(), Error> {
        if domain >= 10 {
            return Ok(());
        }
        let config = self.d2(DOMAIN0_PG_CONFIG + 2 * domain);
        self.regs
            .update(config, DOMAIN_POWER_GATE, DOMAIN_POWER_GATE)?;
        self.regs
            // linux-lit: 4=(mmDOMAIN0_PG_STATUS - mmDOMAIN0_PG_CONFIG) * 4
            // linux-lit: 30=DOMAIN0_PG_STATUS__DOMAIN0_PGFSM_PWR_STATUS__SHIFT
            // linux: n/a (2 = PGFSM_POWER_OFF, literal in dcn10_hwseq.c)
            .wait(config + 4, DOMAIN_PGFSM_PWR_STATUS, 2 << 30, 1, 1000)
            .await?;
        Ok(())
    }
    /// `dcn20_plane_atomic_disable` for a pipe whose MPCC was just reset.
    async fn disable_plane(&mut self, pipe: u8, tg_enabled: bool) -> Result<(), Error> {
        // dcn10_wait_for_mpcc_disconnect: the MPCC idles (when its OTG runs),
        // then the HUBP is blanked.
        if tg_enabled {
            let status = self.d3(MPCC_STATUS + u64::from(pipe) * MPCC_STRIDE);
            self.regs
                .wait(status, MPCC_IDLE, MPCC_IDLE, 1, 100_000)
                .await?;
        }
        // SAFETY: the takeover holds the whole display engine.
        let mut hubp = unsafe { Hubp::new(self.gpu, self.regs.authority, pipe) }?;
        hubp.blank().await?;
        let p = u64::from(pipe);
        self.regs.update(
            self.d2(HUBP_CLK_CNTL + p * HUBP_STRIDE),
            HUBP_CLOCK_ENABLE,
            0,
        )?;
        self.regs
            .update(self.d2(DPP_CONTROL + p * DPP_STRIDE), DPP_CLOCK_ENABLE, 0)?;
        // dcn10_plane_atomic_power_down.
        let request = self.d2(DC_IP_REQUEST_CNTL);
        self.regs.write(request, IP_REQUEST_EN)?;
        self.gate(2 * p + 1).await?;
        self.gate(2 * p).await?;
        self.regs.write(request, 0)
    }
    /// `optc3_tg_init`.
    fn tg_init(&mut self, pipe: u8) -> Result<(), Error> {
        self.regs.update(
            self.otg(OTG_DOUBLE_BUFFER_CONTROL, pipe),
            OTG_DRR_TIMING_DBUF_UPDATE_MODE,
            // linux: n/a (mode 2, literal in dcn30_optc.c:optc3_set_timing_double_buffer)
            2 << OTG_DRR_TIMING_DBUF_UPDATE_MODE.trailing_zeros(),
        )?;
        self.regs.update(
            self.d2(ODM_INPUT_GLOBAL_CONTROL + u64::from(pipe) * ODM_STRIDE),
            OPTC_UNDERFLOW_CLEAR,
            OPTC_UNDERFLOW_CLEAR,
        )
    }
    /// `dcn10_init_pipes` with no seamless boot.
    async fn init_pipes(&mut self) -> Result<u8, Error> {
        let mut enabled = 0u8;
        for pipe in 0..PIPES {
            if self.otg_enabled(pipe)? {
                enabled |= 1 << pipe;
                self.init_blank(pipe).await?;
                self.lock(pipe, true).await?;
            }
        }
        for mpcc in 0..PIPES {
            self.mpc_init(mpcc)?;
        }
        for pipe in 0..PIPES {
            let running = self.otg_enabled(pipe)?;
            if running {
                self.lock(pipe, false).await?;
            }
            self.disable_plane(pipe, running).await?;
            self.tg_init(pipe)?;
        }
        Ok(enabled)
    }
    fn dig(&self, reg: u64, transmitter: u8) -> u64 {
        self.d2(reg + u64::from(transmitter) * DIG_STRIDE)
    }
    fn dig_enabled(&mut self, transmitter: u8) -> Result<bool, Error> {
        Ok(self.regs.read(self.dig(DIG_BE_EN_CNTL, transmitter))? & DIG_ENABLE != 0)
    }
    /// `enc1_stream_encoder_dp_blank` on the frontend a DP backend sources
    /// (`dcn10_get_dig_frontend`).
    async fn blank_dp(&mut self, transmitter: u8) -> Result<(), Error> {
        let be = self.regs.read(self.dig(DIG_BE_CNTL, transmitter))?;
        if be & DIG_MODE != 0 {
            return Ok(());
        }
        // linux-lit: 8=DIG0_DIG_BE_CNTL__DIG_FE_SOURCE_SELECT__SHIFT
        let sources = (be & DIG_FE_SOURCE_SELECT) >> 8;
        if sources == 0 {
            return Ok(());
        }
        let fe = sources.trailing_zeros() as u8;
        crate::amdgpu_dcn30_dp::blank_stream(&mut self.regs, self.dcn2, fe).await
    }
    /// `dce110_power_down`'s encoder and controller halves.
    async fn power_down(&mut self, tables: &Tables<'_>, links: &[Connector]) -> Result<(), Error> {
        for link in links {
            let transmitter = link.path.transmitter;
            if link.signal == Signal::DisplayPort && self.dig_enabled(transmitter)? {
                self.blank_dp(transmitter).await?;
            }
            // dcn10_link_encoder_disable_output(SIGNAL_TYPE_NONE): only an
            // enabled DIG is touched, and NONE is not DP, so no encoder reset.
            if self.dig_enabled(transmitter)? {
                let bus = crate::amdgpu_navi22_modeset::bios_bus(self.gpu, self.regs.authority);
                tables.transmitter(
                    bus,
                    &Transmitter {
                        action: TransmitterAction::Disable,
                        transmitter,
                        mode: TransmitterMode::Dvi,
                        lanes: 0,
                        hpd: link.hpd,
                        connector: link.object_id(),
                        symbol_khz: 0,
                    },
                )?;
            }
        }
        for pipe in 0..PIPES {
            // SAFETY: the takeover holds the whole display engine.
            let mut otg = unsafe { Otg::new(self.gpu, self.regs.authority, pipe) }?;
            // optc1_disable_crtc waits OTG_BUSY up to 100 ms; Linux logs.
            match otg.disable().await {
                Ok(()) | Err(BlockError::Timeout) => {}
                Err(error) => return Err(Error::Block(error)),
            }
        }
        Ok(())
    }
    /// Steps 2–5 of the module description, after golden init.
    pub(crate) async fn retire(
        &mut self,
        tables: &Tables<'_>,
        links: &[Connector],
    ) -> Result<Inherited, Error> {
        let mut digs = 0u8;
        for link in links {
            self.link_hw_init(link.path.transmitter)?;
        }
        for transmitter in 0..STREAMS {
            if self.dig_enabled(transmitter)? {
                digs |= 1 << transmitter;
            }
        }
        self.enable_power_gating_plane()?;
        let otgs = self.init_pipes().await?;
        if digs != 0 {
            self.power_down(tables, links).await?;
        }
        Ok(Inherited { otgs, digs })
    }
    /// Every DP stream, DIG backend and OTG idle: what the clock owner and
    /// a new stream require.
    pub(crate) fn check_idle(&mut self) -> Result<(), Error> {
        for i in 0..PIPES {
            if self.otg_enabled(i)? || self.dig_enabled(i)? {
                return Err(Error::Busy);
            }
            let stream = self.d2(DP_VID_STREAM_CNTL + u64::from(i) * DIG_STRIDE);
            // linux-lit: 1=DP0_DP_VID_STREAM_CNTL__DP_VID_STREAM_ENABLE_MASK
            if self.regs.read(stream)? & 1 != 0 {
                return Err(Error::Busy);
            }
        }
        Ok(())
    }
}
